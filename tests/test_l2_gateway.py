"""The host-enforced L2 gateway.

This is the component that makes "the VM cannot reach the internet when
WireGuard is unavailable" true regardless of what the guest does, so the tests
are written as attempted escapes: every frame that is not WireGuard-to-the-
gateway must be dropped, and the drop reason must say why.
"""

from __future__ import annotations

import socket
import struct

import pytest

from agentsandbox.vm.gateway import (
    ARP_REQUEST,
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    ETHERTYPE_IPV6,
    EthernetFrame,
    GatewayConfig,
    L2Gateway,
    build_arp_reply,
    build_ipv4_udp,
    checksum16,
    mac_to_bytes,
    parse_arp,
    parse_ethernet,
    parse_ipv4_udp,
)

GUEST_MAC = mac_to_bytes("02:00:00:00:00:02")
GATEWAY_MAC = mac_to_bytes("02:00:00:00:00:01")
WG_PAYLOAD = b"\x01\x00\x00\x00wireguard-handshake-initiation"


@pytest.fixture
def relayed():
    return []


@pytest.fixture
def gateway(relayed):
    return L2Gateway(GatewayConfig(), relay=relayed.append)


def guest_udp_frame(
    dst_ip="192.168.127.1", dst_port=51820, src_ip="192.168.127.2", src_port=41234, payload=WG_PAYLOAD
) -> bytes:
    packet = build_ipv4_udp(src_ip, dst_ip, src_port, dst_port, payload)
    return EthernetFrame(GATEWAY_MAC, GUEST_MAC, ETHERTYPE_IPV4, packet).pack()


# -- the one thing that is allowed ------------------------------------------


def test_wireguard_to_the_gateway_is_relayed(gateway, relayed):
    assert gateway.handle_frame(guest_udp_frame()) == []
    assert relayed == [WG_PAYLOAD]
    assert gateway.stats.relayed == 1
    assert gateway.stats.dropped == 0


def test_arp_for_the_gateway_is_answered(gateway):
    request = build_arp_reply(GUEST_MAC, "192.168.127.2", b"\x00" * 6, "192.168.127.1")
    request = bytearray(request)
    struct.pack_into("!H", request, 6, ARP_REQUEST)
    frame = EthernetFrame(b"\xff" * 6, GUEST_MAC, ETHERTYPE_ARP, bytes(request)).pack()

    replies = gateway.handle_frame(frame)
    assert len(replies) == 1
    parsed = parse_ethernet(replies[0])
    arp = parse_arp(parsed.payload)
    assert arp["sender_ip"] == "192.168.127.1"
    assert arp["sender_mac"] == GATEWAY_MAC
    assert parsed.dst == GUEST_MAC


# -- everything else ---------------------------------------------------------


def test_udp_to_any_other_host_is_dropped(gateway, relayed):
    gateway.handle_frame(guest_udp_frame(dst_ip="8.8.8.8", dst_port=53))
    assert relayed == []
    assert gateway.stats.drops_by_reason["not_wireguard_endpoint"] == 1


def test_udp_to_the_gateway_on_another_port_is_dropped(gateway, relayed):
    gateway.handle_frame(guest_udp_frame(dst_port=53))
    assert relayed == []
    assert gateway.stats.drops_by_reason["not_wireguard_endpoint"] == 1


def test_tcp_is_dropped(gateway, relayed):
    """No TCP path exists at all - not even to the gateway."""
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        40,
        1,
        0,
        64,
        6,  # TCP
        0,
        socket.inet_aton("192.168.127.2"),
        socket.inet_aton("192.168.127.1"),
    )
    tcp = struct.pack("!HHLLBBHHH", 12345, 443, 0, 0, 5 << 4, 0x02, 1024, 0, 0)
    frame = EthernetFrame(GATEWAY_MAC, GUEST_MAC, ETHERTYPE_IPV4, ip_header + tcp).pack()
    gateway.handle_frame(frame)
    assert relayed == []
    assert gateway.stats.drops_by_reason["not_ipv4_udp"] == 1


def test_icmp_is_dropped(gateway, relayed):
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 28, 1, 0, 64, 1, 0,
        socket.inet_aton("192.168.127.2"),
        socket.inet_aton("8.8.8.8"),
    )
    frame = EthernetFrame(GATEWAY_MAC, GUEST_MAC, ETHERTYPE_IPV4, ip_header + b"\x08\x00\x00\x00").pack()
    gateway.handle_frame(frame)
    assert relayed == []


def test_ipv6_is_dropped_wholesale(gateway, relayed):
    frame = EthernetFrame(GATEWAY_MAC, GUEST_MAC, ETHERTYPE_IPV6, b"\x60" + b"\x00" * 39).pack()
    gateway.handle_frame(frame)
    assert relayed == []
    assert gateway.stats.drops_by_reason["ipv6"] == 1


def test_source_address_spoofing_is_dropped(gateway, relayed):
    gateway.handle_frame(guest_udp_frame(src_ip="10.0.0.9"))
    assert relayed == []
    assert gateway.stats.drops_by_reason["spoofed_source"] == 1


def test_fragmented_packets_are_dropped(gateway, relayed):
    """A fragment could hide the real destination port from this check."""
    packet = bytearray(build_ipv4_udp("192.168.127.2", "192.168.127.1", 41234, 51820, WG_PAYLOAD))
    struct.pack_into("!H", packet, 6, 0x2000)  # more-fragments
    frame = EthernetFrame(GATEWAY_MAC, GUEST_MAC, ETHERTYPE_IPV4, bytes(packet)).pack()
    gateway.handle_frame(frame)
    assert relayed == []
    assert gateway.stats.drops_by_reason["not_ipv4_udp"] == 1


def test_arp_for_anything_but_the_gateway_is_dropped(gateway):
    request = bytearray(build_arp_reply(GUEST_MAC, "192.168.127.2", b"\x00" * 6, "192.168.127.55"))
    struct.pack_into("!H", request, 6, ARP_REQUEST)
    frame = EthernetFrame(b"\xff" * 6, GUEST_MAC, ETHERTYPE_ARP, bytes(request)).pack()
    assert gateway.handle_frame(frame) == []
    assert gateway.stats.drops_by_reason["arp_other_target"] == 1


def test_unknown_ethertypes_are_dropped(gateway):
    frame = EthernetFrame(GATEWAY_MAC, GUEST_MAC, 0x8100, b"\x00" * 20).pack()  # VLAN tag
    assert gateway.handle_frame(frame) == []
    assert gateway.stats.dropped == 1


def test_truncated_frames_are_dropped(gateway):
    assert gateway.handle_frame(b"\x00\x01\x02") == []
    assert gateway.stats.drops_by_reason["malformed_ethernet"] == 1


def test_nothing_gets_out_before_the_guest_has_sent_anything(gateway):
    """With no learned guest, replies have nowhere to go - fail closed."""
    fresh = L2Gateway(GatewayConfig(guest_mac=""), relay=lambda payload: None)
    assert fresh.build_return_frame(b"reply") is None


# -- return path -------------------------------------------------------------


def test_return_frames_are_addressed_to_the_learned_guest(gateway):
    gateway.handle_frame(guest_udp_frame(src_port=51999))
    frame = gateway.build_return_frame(b"wg-response")

    parsed = parse_ethernet(frame)
    assert parsed.dst == GUEST_MAC
    assert parsed.src == GATEWAY_MAC
    datagram = parse_ipv4_udp(parsed.payload)
    assert datagram.src_ip == "192.168.127.1"
    assert datagram.dst_ip == "192.168.127.2"
    assert datagram.src_port == 51820
    assert datagram.dst_port == 51999  # the port the guest actually used
    assert datagram.payload == b"wg-response"


def test_built_packets_have_valid_checksums():
    packet = build_ipv4_udp("192.168.127.1", "192.168.127.2", 51820, 41234, b"payload")
    # Checksumming a header that already contains its checksum yields zero.
    assert checksum16(packet[:20]) == 0

    pseudo = (
        socket.inet_aton("192.168.127.1")
        + socket.inet_aton("192.168.127.2")
        + struct.pack("!BBH", 0, 17, len(packet) - 20)
    )
    assert checksum16(pseudo + packet[20:]) == 0


def test_stats_are_reported_for_audit(gateway, relayed):
    gateway.handle_frame(guest_udp_frame())
    gateway.handle_frame(guest_udp_frame(dst_ip="1.1.1.1"))
    assert gateway.stats.frames_in == 2
    assert gateway.stats.relayed == 1
    assert gateway.stats.dropped == 1


def test_stopping_the_runner_does_not_leave_the_thread_on_dead_sockets(tmp_path):
    """Teardown used to close the sockets under a selecting thread (EBADF)."""

    from agentsandbox.vm.gateway import GatewayRunner

    runner = GatewayRunner(GatewayConfig(), tmp_path / "guest-net.sock")
    runner.start()
    thread = runner.run_in_thread()
    assert thread.is_alive()

    runner.stop()
    thread.join(timeout=3)
    assert not thread.is_alive()
    assert not (tmp_path / "guest-net.sock").exists()
    # And a second stop is harmless.
    runner.stop()


def test_runner_survives_being_stopped_before_it_ever_ran(tmp_path):
    from agentsandbox.vm.gateway import GatewayRunner

    runner = GatewayRunner(GatewayConfig(), tmp_path / "n.sock")
    runner.start()
    runner.stop()


# -- DHCP --------------------------------------------------------------------


def dhcp_frame(message_type: int, xid: int = 0xAABBCCDD) -> bytes:
    """A guest DHCPDISCOVER/DHCPREQUEST, as networkd would send it."""
    from agentsandbox.vm.gateway import BOOTP, DHCP_MAGIC, OPT_END, OPT_MSGTYPE

    header = BOOTP.pack(
        1, 1, 6, 0, xid, 0, 0x8000,
        b"\x00" * 4, b"\x00" * 4, b"\x00" * 4, b"\x00" * 4,
        GUEST_MAC + b"\x00" * 10, b"\x00" * 64, b"\x00" * 128,
    )
    options = DHCP_MAGIC + bytes([OPT_MSGTYPE, 1, message_type, OPT_END])
    packet = build_ipv4_udp("0.0.0.0", "255.255.255.255", 68, 67, header + options)
    return EthernetFrame(b"\xff" * 6, GUEST_MAC, ETHERTYPE_IPV4, packet).pack()


def dhcp_options(reply_frame: bytes) -> dict:
    from agentsandbox.vm.gateway import BOOTP, DHCP_MAGIC, OPT_END

    payload = parse_ipv4_udp(parse_ethernet(reply_frame).payload).payload
    fields = BOOTP.unpack_from(payload)
    options, index = {}, BOOTP.size + 4
    assert payload[BOOTP.size : BOOTP.size + 4] == DHCP_MAGIC
    while index < len(payload) and payload[index] != OPT_END:
        code, length = payload[index], payload[index + 1]
        options[code] = payload[index + 2 : index + 2 + length]
        index += 2 + length
    return {"yiaddr": socket.inet_ntoa(fields[8]), "options": options, "xid": fields[4]}


def test_dhcp_discover_is_offered_an_address(gateway, relayed):
    """Without this the guest waits forever for a lease and boot stalls."""
    replies = gateway.handle_frame(dhcp_frame(1))
    assert len(replies) == 1
    parsed = dhcp_options(replies[0])
    assert parsed["yiaddr"] == "192.168.127.2"
    assert parsed["options"][53] == bytes([2])  # OFFER
    assert relayed == []  # nothing left the host


def test_dhcp_request_is_acknowledged(gateway):
    parsed = dhcp_options(gateway.handle_frame(dhcp_frame(3))[0])
    assert parsed["options"][53] == bytes([5])  # ACK
    assert parsed["xid"] == 0xAABBCCDD  # echoed back, or the client ignores it


def test_dhcp_never_hands_out_a_router_or_dns(gateway):
    """The guest's only default route must come from wg-quick."""
    parsed = dhcp_options(gateway.handle_frame(dhcp_frame(1))[0])
    assert 3 not in parsed["options"], "router option would create a bypass route"
    assert 6 not in parsed["options"], "dns option would point outside the tunnel"
    assert parsed["options"][1] == socket.inet_aton("255.255.255.0")
    assert parsed["options"][54] == socket.inet_aton("192.168.127.1")


def test_other_dhcp_message_types_are_dropped(gateway):
    assert gateway.handle_frame(dhcp_frame(7)) == []  # RELEASE
    assert gateway.stats.drops_by_reason["dhcp_type_7"] == 1


def test_malformed_dhcp_is_dropped(gateway):
    packet = build_ipv4_udp("0.0.0.0", "255.255.255.255", 68, 67, b"too short")
    frame = EthernetFrame(b"\xff" * 6, GUEST_MAC, ETHERTYPE_IPV4, packet).pack()
    assert gateway.handle_frame(frame) == []
    assert gateway.stats.drops_by_reason["malformed_dhcp"] == 1


def test_dhcp_to_a_port_that_is_not_dhcp_is_still_dropped(gateway, relayed):
    gateway.handle_frame(guest_udp_frame(dst_port=67, src_port=1234))
    assert relayed == []
    assert gateway.stats.dropped == 1


def test_gateway_stats_are_published_for_other_processes(tmp_path):
    """`asbx box status` runs in a second terminal and must still see them."""
    import json

    from agentsandbox.vm.gateway import GatewayRunner

    stats = tmp_path / "gateway-stats.json"
    runner = GatewayRunner(GatewayConfig(), tmp_path / "n.sock", stats_path=stats)
    runner.start()
    runner.gateway.handle_frame(guest_udp_frame(dst_ip="8.8.8.8"))
    runner.stop()

    published = json.loads(stats.read_text())
    assert published["dropped"] == 1
    assert published["drops_by_reason"]["not_wireguard_endpoint"] == 1


def test_the_socket_buffers_are_widened():
    """A container image pull wedged the guest's NIC.

    The guest transmits into a unix datagram socket we drain from Python. With
    the default buffer, sustained traffic overran it, vfkit could no longer
    write, and virtio_net reported NETDEV WATCHDOG transmit timeouts that never
    cleared - the interface was dead for the rest of the session.
    """
    import socket as _socket

    from agentsandbox.vm.gateway import _widen_buffers

    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    try:
        before = sock.getsockopt(_socket.SOL_SOCKET, _socket.SO_RCVBUF)
        _widen_buffers(sock)
        after = sock.getsockopt(_socket.SOL_SOCKET, _socket.SO_RCVBUF)
        assert after >= before
    finally:
        sock.close()


def test_frames_the_host_cannot_deliver_are_counted():
    """It used to be a debug log nobody reads. The count is what says the
    relay is falling behind, before the guest's NIC gives up."""
    from agentsandbox.vm.gateway import GatewayStats

    stats = GatewayStats()
    assert stats.send_failed == 0
    stats.send_failed += 1
    assert stats.send_failed == 1


def test_a_wakeup_drains_more_than_one_frame():
    """One recvfrom per select() is a poll round trip per frame, which is not
    fast enough to keep our receive buffer empty under load."""
    import inspect

    from agentsandbox.vm.gateway import GatewayRunner, _DRAIN_BATCH

    assert _DRAIN_BATCH > 1
    assert "_DRAIN_BATCH" in inspect.getsource(GatewayRunner._on_guest_frame)
    assert "_DRAIN_BATCH" in inspect.getsource(GatewayRunner._on_wireguard_reply)


def test_draining_an_empty_socket_does_not_block(tmp_path):
    """Emptying a socket must cost nothing, or the other one goes unread.

    The drain loop stops when a recvfrom raises. On a socket with a timeout,
    that raise arrives half a second later - and for that half second the
    reply waiting on the *other* socket is not looked at. Every hop through
    the relay then cost 0.5s, which a guest sees as a curl taking seconds
    while a bulk download - where neither socket is ever empty - stays fast.
    """
    import time

    from agentsandbox.vm.gateway import GatewayRunner

    runner = GatewayRunner(GatewayConfig(), tmp_path / "n.sock")
    runner.start()
    try:
        assert runner._net.gettimeout() == 0.0  # non-blocking, not 0.5s
        assert runner._wg.gettimeout() == 0.0
        started = time.perf_counter()
        runner._on_guest_frame()
        runner._on_wireguard_reply()
        assert time.perf_counter() - started < 0.1
    finally:
        runner.stop()
