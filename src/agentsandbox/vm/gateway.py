"""The host-enforced L2 gateway - where "fail closed" is actually implemented.

vfkit can attach the guest's NIC to a unix datagram socket instead of a NAT
device (``--device virtio-net,unixSocketPath=...``).  Every Ethernet frame the
guest emits therefore arrives *here*, in a host process the guest does not
control, and only what this file chooses to relay reaches the outside world.

The policy is one rule long:

    UDP to the WireGuard endpoint is relayed. ARP for the gateway is answered,
    and DHCP is served locally (an address and a netmask - never a router or a
    DNS server). Everything else is dropped.

That is what makes the spec's first acceptance criterion true by construction
rather than by guest configuration: with mitmproxy down, the guest's packets
have nowhere to go, and no amount of root inside the VM changes that.  The
guest's own nftables ruleset is defence in depth, not the control.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import struct
import threading
from dataclasses import dataclass, field
from typing import Callable

logger = logging.getLogger(__name__)

ETH_HEADER = struct.Struct("!6s6sH")
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD

ARP_STRUCT = struct.Struct("!HHBBH6s4s6s4s")
ARP_REQUEST = 1
ARP_REPLY = 2

IPPROTO_UDP = 17
IP_HEADER = struct.Struct("!BBHHHBBH4s4s")
UDP_HEADER = struct.Struct("!HHHH")

#: Addresses the guest sees. Deliberately not the Mac's real LAN address: the
#: guest never learns anything about the host's network.
DEFAULT_GATEWAY_IP = "192.168.127.1"
DEFAULT_GUEST_IP = "192.168.127.2"
DEFAULT_NETMASK = "255.255.255.0"
#: Locally administered MACs, so they cannot collide with real hardware.
DEFAULT_GATEWAY_MAC = "02:00:00:00:00:01"
DEFAULT_GUEST_MAC = "02:00:00:00:00:02"
DEFAULT_WG_PORT = 51820

BROADCAST_MAC = b"\xff" * 6


def mac_to_bytes(mac: str) -> bytes:
    return bytes(int(part, 16) for part in mac.split(":"))


def mac_to_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def ip_to_bytes(ip: str) -> bytes:
    return socket.inet_aton(ip)


def checksum16(data: bytes) -> int:
    """Standard internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


@dataclass
class EthernetFrame:
    dst: bytes
    src: bytes
    ethertype: int
    payload: bytes

    def pack(self) -> bytes:
        return ETH_HEADER.pack(self.dst, self.src, self.ethertype) + self.payload


def parse_ethernet(frame: bytes) -> EthernetFrame | None:
    if len(frame) < ETH_HEADER.size:
        return None
    dst, src, ethertype = ETH_HEADER.unpack_from(frame)
    return EthernetFrame(dst, src, ethertype, frame[ETH_HEADER.size :])


@dataclass
class UdpDatagram:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    payload: bytes


def parse_ipv4_udp(payload: bytes) -> UdpDatagram | None:
    """Parse an IPv4/UDP datagram, rejecting anything unusual.

    Fragments are rejected outright: a fragmented first packet would let a
    guest hide the UDP port from this check and reassemble upstream.
    """
    if len(payload) < IP_HEADER.size:
        return None
    ver_ihl, _tos, total_len, _ident, flags_frag, _ttl, proto, _csum, src, dst = (
        IP_HEADER.unpack_from(payload)
    )
    if ver_ihl >> 4 != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < IP_HEADER.size or len(payload) < ihl:
        return None
    if proto != IPPROTO_UDP:
        return None
    more_fragments = bool(flags_frag & 0x2000)
    fragment_offset = flags_frag & 0x1FFF
    if more_fragments or fragment_offset:
        return None
    body = payload[ihl:total_len] if total_len and total_len <= len(payload) else payload[ihl:]
    if len(body) < UDP_HEADER.size:
        return None
    src_port, dst_port, udp_len, _udp_csum = UDP_HEADER.unpack_from(body)
    data = body[UDP_HEADER.size : udp_len] if udp_len >= UDP_HEADER.size else body[UDP_HEADER.size :]
    return UdpDatagram(
        src_ip=socket.inet_ntoa(src),
        dst_ip=socket.inet_ntoa(dst),
        src_port=src_port,
        dst_port=dst_port,
        payload=data,
    )


def build_ipv4_udp(
    src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes, ident: int = 0
) -> bytes:
    udp_len = UDP_HEADER.size + len(payload)
    src_raw, dst_raw = ip_to_bytes(src_ip), ip_to_bytes(dst_ip)

    pseudo = src_raw + dst_raw + struct.pack("!BBH", 0, IPPROTO_UDP, udp_len)
    udp = UDP_HEADER.pack(src_port, dst_port, udp_len, 0) + payload
    udp_csum = checksum16(pseudo + udp) or 0xFFFF  # 0 means "no checksum" in UDP
    udp = UDP_HEADER.pack(src_port, dst_port, udp_len, udp_csum) + payload

    total_len = IP_HEADER.size + udp_len
    header = IP_HEADER.pack(
        0x45, 0, total_len, ident & 0xFFFF, 0x4000, 64, IPPROTO_UDP, 0, src_raw, dst_raw
    )
    header = IP_HEADER.pack(
        0x45,
        0,
        total_len,
        ident & 0xFFFF,
        0x4000,
        64,
        IPPROTO_UDP,
        checksum16(header),
        src_raw,
        dst_raw,
    )
    return header + udp


def parse_arp(payload: bytes) -> dict | None:
    if len(payload) < ARP_STRUCT.size:
        return None
    htype, ptype, hlen, plen, op, sha, spa, tha, tpa = ARP_STRUCT.unpack_from(payload)
    if htype != 1 or ptype != ETHERTYPE_IPV4 or hlen != 6 or plen != 4:
        return None
    return {
        "op": op,
        "sender_mac": sha,
        "sender_ip": socket.inet_ntoa(spa),
        "target_mac": tha,
        "target_ip": socket.inet_ntoa(tpa),
    }


def build_arp_reply(
    sender_mac: bytes, sender_ip: str, target_mac: bytes, target_ip: str
) -> bytes:
    return ARP_STRUCT.pack(
        1,
        ETHERTYPE_IPV4,
        6,
        4,
        ARP_REPLY,
        sender_mac,
        ip_to_bytes(sender_ip),
        target_mac,
        ip_to_bytes(target_ip),
    )


DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68
DHCP_MAGIC = b"\x63\x82\x53\x63"
BOOTP = struct.Struct("!BBBBIHH4s4s4s4s16s64s128s")
DHCP_DISCOVER, DHCP_OFFER, DHCP_REQUEST, DHCP_ACK = 1, 2, 3, 5
#: Option numbers we answer with. Note what is *absent*: no router (3) and no
#: DNS (6). The guest must not learn a default route from us - the only one it
#: ever gets is the tunnel's, installed by wg-quick, and DNS lives at the far
#: end of that tunnel.
OPT_SUBNET, OPT_LEASE, OPT_MSGTYPE, OPT_SERVERID, OPT_MTU, OPT_END = 1, 51, 53, 54, 26, 255


def parse_dhcp(payload: bytes) -> dict | None:
    """Parse a BOOTP/DHCP message into the few fields we care about."""
    if len(payload) < BOOTP.size + 4:
        return None
    (op, htype, hlen, _hops, xid, _secs, flags, _ci, _yi, _si, _gi, chaddr, _sn, _file) = (
        BOOTP.unpack_from(payload)
    )
    if op != 1 or htype != 1 or hlen != 6:  # BOOTREQUEST over ethernet only
        return None
    if payload[BOOTP.size : BOOTP.size + 4] != DHCP_MAGIC:
        return None

    options: dict[int, bytes] = {}
    index = BOOTP.size + 4
    while index < len(payload):
        code = payload[index]
        if code == OPT_END:
            break
        if code == 0:  # pad
            index += 1
            continue
        if index + 1 >= len(payload):
            break
        length = payload[index + 1]
        options[code] = payload[index + 2 : index + 2 + length]
        index += 2 + length

    message_type = options.get(OPT_MSGTYPE, b"")
    return {
        "xid": xid,
        "flags": flags,
        "client_mac": chaddr[:6],
        "type": message_type[0] if message_type else 0,
        "options": options,
    }


def build_dhcp_reply(request: dict, reply_type: int, guest_ip: str, gateway_ip: str, mtu: int = 1500,
                     lease_seconds: int = 86400) -> bytes:
    """Build a DHCPOFFER/DHCPACK carrying an address and nothing else."""
    header = BOOTP.pack(
        2,  # BOOTREPLY
        1,
        6,
        0,
        request["xid"],
        0,
        request["flags"],
        b"\x00" * 4,  # ciaddr
        ip_to_bytes(guest_ip),  # yiaddr - the address we are handing out
        ip_to_bytes(gateway_ip),  # siaddr
        b"\x00" * 4,  # giaddr
        request["client_mac"] + b"\x00" * 10,
        b"\x00" * 64,
        b"\x00" * 128,
    )
    options = b"".join(
        [
            DHCP_MAGIC,
            bytes([OPT_MSGTYPE, 1, reply_type]),
            bytes([OPT_SERVERID, 4]) + ip_to_bytes(gateway_ip),
            bytes([OPT_LEASE, 4]) + struct.pack("!I", lease_seconds),
            bytes([OPT_SUBNET, 4]) + ip_to_bytes(DEFAULT_NETMASK),
            bytes([OPT_MTU, 2]) + struct.pack("!H", mtu),
            bytes([OPT_END]),
        ]
    )
    return header + options


#: Frames to pull off a socket per select() wakeup. The guest's NIC is a
#: datagram socket, and one recvfrom per poll could not keep up with a
#: container image pull - our receive buffer filled, vfkit could not write into
#: it, and the guest's virtio transmit queue timed out for good.
_DRAIN_BATCH = 256

#: 4 MiB each way. The default for a unix datagram socket on macOS is small
#: enough that a few hundred milliseconds of sustained traffic overruns it, and
#: an overrun does not slow the guest down - it wedges its NIC.
_SOCKET_BUFFER = 4 * 1024 * 1024


def _widen_buffers(sock: socket.socket) -> None:
    """Ask for a large send and receive buffer, taking what we are given.

    The kernel silently caps this, so the request is best-effort by design -
    but going from the default to whatever the cap is buys the headroom that
    keeps backpressure away from the guest's virtio queue.
    """
    for option in (socket.SO_RCVBUF, socket.SO_SNDBUF):
        for size in (_SOCKET_BUFFER, 1024 * 1024, 256 * 1024):
            try:
                sock.setsockopt(socket.SOL_SOCKET, option, size)
                break
            except OSError:
                continue


@dataclass
class GatewayStats:
    frames_in: int = 0
    frames_out: int = 0
    relayed: int = 0
    returned: int = 0
    dhcp_replies: int = 0
    dropped: int = 0
    #: Frames the host could not hand to the guest, almost always ENOBUFS.
    #: Counted rather than logged at debug: this is the number that says the
    #: relay is falling behind, and it used to be invisible.
    send_failed: int = 0
    drops_by_reason: dict[str, int] = field(default_factory=dict)

    def drop(self, reason: str) -> None:
        self.dropped += 1
        self.drops_by_reason[reason] = self.drops_by_reason.get(reason, 0) + 1


@dataclass
class GatewayConfig:
    """Where the one permitted destination is, and what the guest sees."""

    #: mitmproxy's WireGuard listener on the host.
    wg_host: str = "127.0.0.1"
    wg_port: int = DEFAULT_WG_PORT
    #: What the guest addresses as its endpoint (rewritten to the above).
    gateway_ip: str = DEFAULT_GATEWAY_IP
    gateway_port: int = DEFAULT_WG_PORT
    guest_ip: str = DEFAULT_GUEST_IP
    gateway_mac: str = DEFAULT_GATEWAY_MAC
    guest_mac: str = DEFAULT_GUEST_MAC


class L2Gateway:
    """Pure frame-level policy. No sockets - see :class:`GatewayRunner`.

    ``handle_frame`` returns the frames to write back to the guest, and calls
    ``relay`` for the (rare) payloads allowed to leave.  Keeping it side-effect
    free except for that one callback is what makes it testable frame by frame.
    """

    def __init__(self, config: GatewayConfig, relay: Callable[[bytes], None] | None = None) -> None:
        self.config = config
        self.relay = relay or (lambda payload: None)
        self.stats = GatewayStats()
        self.gateway_mac = mac_to_bytes(config.gateway_mac)
        self.guest_mac: bytes | None = (
            mac_to_bytes(config.guest_mac) if config.guest_mac else None
        )
        #: Source port the guest's WireGuard is using; learned from its first
        #: packet and used to address the return traffic.
        self.guest_wg_port: int | None = None
        self._ident = 0

    # -- guest -> host -------------------------------------------------------

    def handle_frame(self, raw: bytes) -> list[bytes]:
        self.stats.frames_in += 1
        frame = parse_ethernet(raw)
        if frame is None:
            self.stats.drop("malformed_ethernet")
            return []

        if frame.ethertype == ETHERTYPE_ARP:
            return self._handle_arp(frame)
        if frame.ethertype == ETHERTYPE_IPV6:
            # No IPv6 path exists through this gateway, so an IPv6 default
            # route inside the guest can never become a bypass.
            self.stats.drop("ipv6")
            return []
        if frame.ethertype != ETHERTYPE_IPV4:
            self.stats.drop(f"ethertype_{frame.ethertype:#06x}")
            return []

        datagram = parse_ipv4_udp(frame.payload)
        if datagram is None:
            self.stats.drop("not_ipv4_udp")
            return []

        # DHCP is answered here rather than relayed. The guest gets an address
        # and a subnet - no router option, no DNS - so even a fully configured
        # interface still has no route off-link until wg-quick installs one.
        if datagram.dst_port == DHCP_SERVER_PORT and datagram.src_port == DHCP_CLIENT_PORT:
            return self._handle_dhcp(frame, datagram)

        if datagram.dst_ip != self.config.gateway_ip or datagram.dst_port != self.config.gateway_port:
            self.stats.drop("not_wireguard_endpoint")
            return []
        if datagram.src_ip != self.config.guest_ip:
            self.stats.drop("spoofed_source")
            return []

        self.guest_mac = frame.src
        self.guest_wg_port = datagram.src_port
        self.stats.relayed += 1
        self.relay(datagram.payload)
        return []

    def _handle_dhcp(self, frame: EthernetFrame, datagram: UdpDatagram) -> list[bytes]:
        request = parse_dhcp(datagram.payload)
        if request is None:
            self.stats.drop("malformed_dhcp")
            return []
        if request["type"] == DHCP_DISCOVER:
            reply_type = DHCP_OFFER
        elif request["type"] == DHCP_REQUEST:
            reply_type = DHCP_ACK
        else:
            # RELEASE, INFORM, DECLINE: nothing to say, and nothing to leak.
            self.stats.drop(f"dhcp_type_{request['type']}")
            return []

        self.guest_mac = frame.src
        self._ident = (self._ident + 1) & 0xFFFF
        payload = build_dhcp_reply(
            request, reply_type, self.config.guest_ip, self.config.gateway_ip
        )
        packet = build_ipv4_udp(
            self.config.gateway_ip,
            "255.255.255.255",
            DHCP_SERVER_PORT,
            DHCP_CLIENT_PORT,
            payload,
            ident=self._ident,
        )
        self.stats.dhcp_replies += 1
        self.stats.frames_out += 1
        return [EthernetFrame(frame.src, self.gateway_mac, ETHERTYPE_IPV4, packet).pack()]

    def _handle_arp(self, frame: EthernetFrame) -> list[bytes]:
        arp = parse_arp(frame.payload)
        if arp is None or arp["op"] != ARP_REQUEST:
            self.stats.drop("arp_not_request")
            return []
        if arp["target_ip"] != self.config.gateway_ip:
            # The guest may only ever learn about the gateway itself.
            self.stats.drop("arp_other_target")
            return []
        self.guest_mac = frame.src
        reply = build_arp_reply(
            sender_mac=self.gateway_mac,
            sender_ip=self.config.gateway_ip,
            target_mac=frame.src,
            target_ip=arp["sender_ip"],
        )
        self.stats.frames_out += 1
        return [EthernetFrame(frame.src, self.gateway_mac, ETHERTYPE_ARP, reply).pack()]

    # -- host -> guest -------------------------------------------------------

    def build_return_frame(self, payload: bytes) -> bytes | None:
        """Wrap a WireGuard reply from mitmproxy back into a guest frame."""
        if self.guest_mac is None or self.guest_wg_port is None:
            return None
        self._ident = (self._ident + 1) & 0xFFFF
        packet = build_ipv4_udp(
            self.config.gateway_ip,
            self.config.guest_ip,
            self.config.gateway_port,
            self.guest_wg_port,
            payload,
            ident=self._ident,
        )
        self.stats.returned += 1
        self.stats.frames_out += 1
        return EthernetFrame(self.guest_mac, self.gateway_mac, ETHERTYPE_IPV4, packet).pack()


class GatewayRunner:
    """Binds the sockets and pumps frames between vfkit and mitmproxy.

    Two sockets, both local:

    * a unix *datagram* socket vfkit attaches the guest NIC to, and
    * a UDP socket to mitmproxy's WireGuard listener on loopback.
    """

    def __init__(self, config: GatewayConfig, socket_path, audit=None, stats_path=None) -> None:
        from pathlib import Path

        self.config = config
        self.socket_path = Path(socket_path)
        #: Counters are also written here, so `asbx session status` can report
        #: them from another terminal instead of only from the process that
        #: owns the gateway.
        self.stats_path = Path(stats_path) if stats_path else None
        self._stats_written = 0.0
        self.audit = audit
        self.gateway = L2Gateway(config, relay=self._relay)
        self._net: socket.socket | None = None
        self._wg: socket.socket | None = None
        self._peer = None
        self._running = False
        self._thread = None

    def _relay(self, payload: bytes) -> None:
        if self._wg is None:
            return
        try:
            self._wg.sendto(payload, (self.config.wg_host, self.config.wg_port))
        except OSError as exc:
            logger.debug("wireguard relay failed: %s", exc)

    def start(self) -> None:
        if self.socket_path.exists():
            self.socket_path.unlink()
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        import os

        old_umask = os.umask(0o177)
        try:
            self._net = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            self._net.bind(str(self.socket_path))
        finally:
            os.umask(old_umask)
        # Non-blocking, not a timeout: the drain loop below stops when a socket
        # is empty, and with a timeout "empty" costs half a second of blocking
        # in which the *other* socket goes unread. select() does the waiting.
        self._net.setblocking(False)
        _widen_buffers(self._net)

        self._wg = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._wg.bind(("127.0.0.1", 0))
        self._wg.setblocking(False)
        _widen_buffers(self._wg)
        self._running = True

    def run_in_thread(self) -> "threading.Thread":
        """Start the pump on its own thread and remember it, so that
        :meth:`stop` can wind it down before closing the sockets underneath it.
        """
        import threading

        self._thread = threading.Thread(target=self.run, name="asbx-l2-gateway", daemon=True)
        self._thread.start()
        return self._thread

    def stop(self) -> None:
        # Order matters: tell the loop to finish and wait for it *before*
        # closing the sockets. Closing first leaves the thread selecting on
        # freed descriptors, which surfaces as EBADF during teardown.
        self._running = False
        self._publish_stats(force=True)
        thread = getattr(self, "_thread", None)
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)
        self._thread = None
        for sock in (self._net, self._wg):
            if sock is not None:
                sock.close()
        self._net = self._wg = None
        self.socket_path.unlink(missing_ok=True)

    def run(self) -> None:
        """Single-threaded select loop over the two sockets."""
        import select

        if self._net is None or self._wg is None:
            self.start()
        while self._running:
            net, wg = self._net, self._wg
            if net is None or wg is None:
                return
            try:
                readable, _, _ = select.select([net, wg], [], [], 0.5)
            except (OSError, ValueError):
                # Sockets closed under us during shutdown; that is not an error.
                if not self._running:
                    return
                raise
            for sock in readable:
                if sock is net:
                    self._on_guest_frame()
                else:
                    self._on_wireguard_reply()
            self._publish_stats()

    def _on_guest_frame(self) -> None:
        """Drain the guest's queue, not one frame per wakeup.

        One recvfrom per select() meant a round trip through poll for every
        single frame. Under a container image pull that is not fast enough:
        our receive buffer fills, vfkit cannot write into it, and the guest's
        virtio transmit queue wedges - NETDEV WATCHDOG, and the interface never
        recovers. Draining in a batch keeps the buffer empty enough that the
        backpressure never reaches the guest's NIC.
        """
        if self._net is None:
            return
        for _ in range(_DRAIN_BATCH):
            try:
                raw, peer = self._net.recvfrom(65535)
            except (BlockingIOError, socket.timeout):
                return
            except OSError:
                return  # socket closed during teardown
            if peer:
                self._peer = peer
            for out in self.gateway.handle_frame(raw):
                self._send_to_guest(out)

    def _on_wireguard_reply(self) -> None:
        if self._wg is None:
            return
        for _ in range(_DRAIN_BATCH):
            try:
                payload, _ = self._wg.recvfrom(65535)
            except (BlockingIOError, socket.timeout):
                return
            except OSError:
                return  # socket closed during teardown
            frame = self.gateway.build_return_frame(payload)
            if frame:
                self._send_to_guest(frame)

    def _send_to_guest(self, frame: bytes) -> None:
        if self._net is None or self._peer is None:
            return
        try:
            self._net.sendto(frame, self._peer)
        except OSError as exc:
            # ENOBUFS here means the guest is not draining fast enough, or we
            # are not. Either way it is a lost frame, and counting it is the
            # difference between "the network went strange" and a number in
            # `asbx diag` that says how far behind the relay is.
            self.gateway.stats.send_failed += 1
            logger.debug("failed to send frame to guest: %s", exc)

    def _publish_stats(self, force: bool = False) -> None:
        import json
        import time

        if self.stats_path is None:
            return
        now = time.monotonic()
        if not force and now - self._stats_written < 2.0:
            return
        self._stats_written = now
        try:
            self.stats_path.write_text(json.dumps(self.snapshot_stats(), indent=2))
        except OSError:
            pass

    def snapshot_stats(self) -> dict:
        stats = self.gateway.stats
        return {
            "frames_in": stats.frames_in,
            "frames_out": stats.frames_out,
            "relayed": stats.relayed,
            "returned": stats.returned,
            "dhcp_replies": stats.dhcp_replies,
            "dropped": stats.dropped,
            "send_failed": stats.send_failed,
            "drops_by_reason": dict(stats.drops_by_reason),
        }


def guest_network_facts(config: GatewayConfig) -> dict:
    """What the guest bootstrap needs to configure its interface statically."""
    network = ipaddress.ip_network(f"{config.guest_ip}/{DEFAULT_NETMASK}", strict=False)
    return {
        "address": f"{config.guest_ip}/{network.prefixlen}",
        "gateway": config.gateway_ip,
        "mac": config.guest_mac,
        "wg_endpoint": f"{config.gateway_ip}:{config.gateway_port}",
    }
