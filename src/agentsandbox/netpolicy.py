"""Destination policy: what the guest is allowed to talk to at all.

This module is the shared truth for both enforcement points:

* the mitmproxy addon, which sees every connection the guest opens, and
* the secrets broker, which re-checks every hop it performs upstream
  (including redirects) so that a bug in the addon is not a bypass.

Everything here fails closed: an address we cannot classify is denied.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from .errors import PolicyDenied

#: Hostnames that must never resolve for the guest regardless of allowlists.
#: These are the classic pivots: the host itself, container/VM host aliases,
#: cloud metadata services, and mDNS names on the user's LAN.
BLOCKED_HOST_SUFFIXES: tuple[str, ...] = (
    "localhost",
    ".localhost",
    ".local",
    ".internal",
    ".lan",
    ".home.arpa",
    ".in-addr.arpa",
    ".ip6.arpa",
)

BLOCKED_HOST_EXACT: frozenset[str] = frozenset(
    {
        "localhost",
        "metadata.google.internal",
        "metadata",
        "host.docker.internal",
        "gateway.docker.internal",
        "host.lima.internal",
        "instance-data",
        "169.254.169.254",
        "[fd00:ec2::254]",
    }
)

#: Cloud metadata endpoints, blocked as literals as well as by range.
METADATA_ADDRESSES: frozenset[str] = frozenset(
    {"169.254.169.254", "169.254.170.2", "fd00:ec2::254", "100.100.100.200"}
)

#: The tunnel subnet mitmproxy's WireGuard mode uses. The guest must never be
#: able to address anything in it other than the DNS responder.
TUNNEL_NETWORK = ipaddress.ip_network("10.0.0.0/24")

#: RFC 6598 carrier-grade NAT space.
CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")

_ALWAYS_ALLOWED_PORTS = (80, 443)


def _as_ip(value: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return None


def classify_ip(ip: ipaddress._BaseAddress) -> str | None:
    """Return a deny reason for an address the guest must not reach, else None.

    IPv4-mapped and 6to4/Teredo forms are unwrapped first: ``::ffff:127.0.0.1``
    is loopback no matter how it is spelled.
    """
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            return classify_ip(ip.ipv4_mapped)
        if ip.sixtofour:
            return classify_ip(ip.sixtofour)
        if ip.teredo:
            return classify_ip(ip.teredo[1])

    if str(ip) in METADATA_ADDRESSES:
        return "blocked_metadata_endpoint"
    if ip.is_loopback:
        return "blocked_loopback"
    if ip.is_link_local:
        return "blocked_link_local"
    if ip.is_multicast:
        return "blocked_multicast"
    if ip.is_unspecified:
        return "blocked_unspecified"
    if ip.is_reserved:
        return "blocked_reserved"
    if isinstance(ip, ipaddress.IPv4Address) and ip in TUNNEL_NETWORK:
        return "blocked_tunnel_network"
    if isinstance(ip, ipaddress.IPv4Address) and ip in CGNAT_NETWORK:
        # Shared address space (RFC 6598). Python stopped reporting it as
        # private, but it is still someone's internal network.
        return "blocked_private_network"
    if ip.is_private:
        # Covers RFC1918, CGNAT (100.64/10), IPv6 ULA (fc00::/7) and friends.
        return "blocked_private_network"
    if not ip.is_global:
        return "blocked_non_global"
    return None


def classify_host(host: str) -> str | None:
    """Deny reason for a hostname on name grounds alone (before resolution)."""
    name = host.strip().strip(".").lower()
    if not name:
        return "blocked_empty_host"
    ip = _as_ip(name)
    if ip is not None:
        return classify_ip(ip)
    if name in BLOCKED_HOST_EXACT:
        return "blocked_host_alias"
    for suffix in BLOCKED_HOST_SUFFIXES:
        if suffix.startswith("."):
            if name.endswith(suffix):
                return "blocked_host_suffix"
        elif name == suffix:
            return "blocked_host_alias"
    return None


def resolve_host(host: str) -> list[ipaddress._BaseAddress]:
    """Resolve a name on the *trusted* side.

    The guest never gets to pick the address a name maps to: mitmproxy's DNS
    responder and the broker both resolve here, and the result is what gets
    validated and connected to.
    """
    literal = _as_ip(host)
    if literal is not None:
        return [literal]
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise PolicyDenied("dns_resolution_failed", f"cannot resolve {host}") from exc
    out: list[ipaddress._BaseAddress] = []
    for info in infos:
        addr = info[4][0]
        ip = _as_ip(addr)
        if ip is not None and ip not in out:
            out.append(ip)
    if not out:
        raise PolicyDenied("dns_resolution_failed", f"cannot resolve {host}")
    return out


def validate_resolved(host: str, ips: Sequence[ipaddress._BaseAddress]) -> None:
    """Reject a name whose resolution touches forbidden space.

    Deliberately *all*, not *any*: a name that resolves to one public and one
    private address is a DNS-rebinding attempt, and allowing the public half
    would let a later re-resolution land on the private one.
    """
    for ip in ips:
        reason = classify_ip(ip)
        if reason:
            raise PolicyDenied(reason, f"{host} resolves into blocked address space")


def resolve_and_validate(host: str) -> list[ipaddress._BaseAddress]:
    reason = classify_host(host)
    if reason:
        raise PolicyDenied(reason, f"{host} is not an allowed destination")
    ips = resolve_host(host)
    validate_resolved(host, ips)
    return ips


def host_matches(host: str, pattern: str) -> bool:
    """Match a hostname against an allowlist entry.

    ``*`` matches everything, ``*.example.com`` matches subdomains but *not*
    ``example.com`` itself, and anything else must match exactly. Case and a
    trailing dot are normalised away; no other globbing is honoured, so a
    pattern can never accidentally match a suffix like ``evil-example.com``.
    """
    host = host.strip().strip(".").lower()
    pattern = pattern.strip().strip(".").lower()
    if pattern == "*":
        return True
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) and len(host) > len(pattern) - 1
    if "*" in pattern:
        return fnmatch.fnmatchcase(host, pattern)
    return host == pattern


def any_host_matches(host: str, patterns: Iterable[str]) -> bool:
    return any(host_matches(host, p) for p in patterns)


@dataclass(frozen=True)
class Destination:
    scheme: str
    host: str
    port: int

    @property
    def origin(self) -> str:
        return f"{self.scheme.lower()}://{self.host.strip().strip('.').lower()}:{self.port}"

    def __str__(self) -> str:  # pragma: no cover - debug aid
        return self.origin


@dataclass
class DestinationPolicy:
    """Session-wide egress rules, evaluated before any capability is consulted.

    ``allow_hosts`` empty means "deny everything", which is the correct
    starting point for an untrusted guest: a session is expected to be given
    the handful of hosts its task needs.
    """

    #: ``["*"]`` means "any public host." The hard blocks (loopback, private,
    #: metadata, link-local) are enforced separately, not through this list.
    allow_hosts: list[str] = field(default_factory=lambda: ["*"])
    deny_hosts: list[str] = field(default_factory=list)
    allow_ports: list[int] = field(default_factory=lambda: list(_ALWAYS_ALLOWED_PORTS))
    #: Non-HTTP TCP/UDP is off unless explicitly enabled: we cannot inspect it,
    #: and the spec says unsupported protocols are denied by default.
    allow_raw_tcp: bool = False
    allow_raw_udp: bool = False
    #: Plain HTTP is allowed by default. Credentials are still never attached
    #: over it — the broker independently requires HTTPS for any
    #: capability-bearing request regardless of this setting.
    allow_plaintext_http: bool = True

    @classmethod
    def from_dict(cls, data: dict) -> DestinationPolicy:
        return cls(
            allow_hosts=list(data.get("allow_hosts", [])),
            deny_hosts=list(data.get("deny_hosts", [])),
            allow_ports=list(data.get("allow_ports", _ALWAYS_ALLOWED_PORTS)),
            allow_raw_tcp=bool(data.get("allow_raw_tcp", False)),
            allow_raw_udp=bool(data.get("allow_raw_udp", False)),
            allow_plaintext_http=bool(data.get("allow_plaintext_http", False)),
        )

    def to_dict(self) -> dict:
        return {
            "allow_hosts": self.allow_hosts,
            "deny_hosts": self.deny_hosts,
            "allow_ports": self.allow_ports,
            "allow_raw_tcp": self.allow_raw_tcp,
            "allow_raw_udp": self.allow_raw_udp,
            "allow_plaintext_http": self.allow_plaintext_http,
        }

    def check(self, dest: Destination, *, resolve: bool = True) -> None:
        """Raise :class:`PolicyDenied` unless the guest may open this connection."""
        host = dest.host.strip().strip(".").lower()
        reason = classify_host(host)
        if reason:
            raise PolicyDenied(reason, f"{host} is not an allowed destination")
        if any_host_matches(host, self.deny_hosts):
            raise PolicyDenied("host_denylisted", f"{host} is denied for this session")
        if not any_host_matches(host, self.allow_hosts):
            raise PolicyDenied("host_not_allowlisted", f"{host} is not in the session allowlist")
        if dest.port not in self.allow_ports:
            raise PolicyDenied("port_not_allowed", f"port {dest.port} is not allowed")
        if dest.scheme.lower() == "http" and not self.allow_plaintext_http:
            raise PolicyDenied("plaintext_http_denied", "plaintext HTTP is disabled")
        if resolve:
            validate_resolved(host, resolve_host(host))

    def allows(self, dest: Destination, *, resolve: bool = True) -> bool:
        try:
            self.check(dest, resolve=resolve)
        except PolicyDenied:
            return False
        return True


def filter_dns_answers(
    answers: Iterable[tuple[str, str]],
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Split resolved answers into (kept, dropped) by address policy.

    Used by the DNS hook so the guest is never *told* about an address it
    would not be allowed to reach - it cannot attempt what it cannot name.
    """
    kept: list[tuple[str, str]] = []
    dropped: list[tuple[str, str]] = []
    for name, addr in answers:
        ip = _as_ip(addr)
        if ip is None or classify_ip(ip):
            dropped.append((name, addr))
        else:
            kept.append((name, addr))
    return kept, dropped


def same_origin(a: Destination, b: Destination) -> bool:
    return a.origin == b.origin


def check_redirect(current: Destination, target: Destination, policy: DestinationPolicy) -> bool:
    """Validate a redirect hop; returns whether credentials may be carried over.

    Raises if the target is not a legal destination at all. A hop that leaves
    the origin is allowed to *proceed* (if policy permits the host) but never
    with the credential attached - that is the "redirects cannot move
    credentials to another origin" rule.
    """
    policy.check(target)
    return same_origin(current, target)
