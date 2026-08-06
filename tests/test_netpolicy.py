"""Destination policy: the guest cannot reach the Mac or the private LAN."""

from __future__ import annotations

import ipaddress

import pytest

from agentsandbox.errors import PolicyDenied
from agentsandbox.netpolicy import (
    Destination,
    DestinationPolicy,
    check_redirect,
    classify_host,
    classify_ip,
    filter_dns_answers,
    host_matches,
    resolve_and_validate,
)


@pytest.mark.parametrize(
    "address,reason",
    [
        ("127.0.0.1", "blocked_loopback"),
        ("::1", "blocked_loopback"),
        ("::ffff:127.0.0.1", "blocked_loopback"),  # IPv4-mapped spelling
        ("10.1.2.3", "blocked_private_network"),
        ("192.168.1.1", "blocked_private_network"),
        ("172.16.5.4", "blocked_private_network"),
        ("100.64.0.1", "blocked_private_network"),  # CGNAT
        ("169.254.1.1", "blocked_link_local"),
        ("169.254.169.254", "blocked_metadata_endpoint"),
        ("fd00:ec2::254", "blocked_metadata_endpoint"),
        ("fe80::1", "blocked_link_local"),
        ("fc00::1", "blocked_private_network"),  # IPv6 ULA
        ("224.0.0.1", "blocked_multicast"),
        ("0.0.0.0", "blocked_unspecified"),
        ("10.0.0.53", "blocked_tunnel_network"),  # the tunnel's own DNS
    ],
)
def test_forbidden_address_space_is_classified(address, reason):
    assert classify_ip(ipaddress.ip_address(address)) == reason


def test_public_addresses_pass():
    assert classify_ip(ipaddress.ip_address("93.184.216.34")) is None
    assert classify_ip(ipaddress.ip_address("2606:2800:220:1::1")) is None


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "foo.localhost",
        "printer.local",
        "host.docker.internal",
        "metadata.google.internal",
        "anything.internal",
        "box.lan",
        "169.254.169.254",
    ],
)
def test_host_aliases_for_the_host_and_lan_are_blocked(host):
    assert classify_host(host) is not None


def test_allowlist_matching_is_not_a_substring_match():
    assert host_matches("api.github.com", "api.github.com")
    assert not host_matches("api.github.com.evil.test", "api.github.com")
    assert not host_matches("evil-api.github.com", "api.github.com")
    assert host_matches("api.example.com", "*.example.com")
    # A wildcard covers subdomains, not the bare domain.
    assert not host_matches("example.com", "*.example.com")
    # Nor a domain that merely ends with the same characters.
    assert not host_matches("notexample.com", "*.example.com")


def test_default_policy_allows_public_hosts_but_still_blocks_dangerous():
    """Default is allow-all public, but private/metadata/loopback are hard blocks."""
    policy = DestinationPolicy()
    assert policy.allows(Destination("https", "api.github.com", 443))
    assert policy.allows(Destination("https", "example.com", 443))
    assert not policy.allows(Destination("https", "127.0.0.1", 443))
    assert not policy.allows(Destination("https", "169.254.169.254", 443))
    assert not policy.allows(Destination("https", "192.168.1.1", 443))


def test_explicit_allowlist_denies_implicitly():
    """Passing --allow flips to restrictive mode."""
    policy = DestinationPolicy(allow_hosts=["api.github.com"])
    policy.check(Destination("https", "api.github.com", 443))
    with pytest.raises(PolicyDenied) as exc:
        policy.check(Destination("https", "example.com", 443))
    assert exc.value.reason == "host_not_allowlisted"


def test_denylist_beats_allowlist():
    policy = DestinationPolicy(allow_hosts=["*.example.com"], deny_hosts=["evil.example.com"])
    policy.check(Destination("https", "api.example.com", 443))
    with pytest.raises(PolicyDenied) as exc:
        policy.check(Destination("https", "evil.example.com", 443))
    assert exc.value.reason == "host_denylisted"


def test_plaintext_http_is_allowed_by_default():
    """HTTP is not refused at the policy level. Credentials are separately blocked by the broker."""
    policy = DestinationPolicy()
    # No exception: HTTP allowed by default
    policy.check(Destination("http", "example.com", 80))


def test_unusual_ports_are_refused(policy):
    with pytest.raises(PolicyDenied) as exc:
        policy.check(Destination("https", "example.com", 8443))
    assert exc.value.reason == "port_not_allowed"


def test_dns_rebinding_is_refused_even_when_one_answer_is_public():
    """A name resolving to both public and private space is not usable.

    Accepting the public answer would leave the private one reachable on the
    next resolution, which is exactly the rebinding attack.
    """
    policy = DestinationPolicy(allow_hosts=["rebind.test"])
    with pytest.raises(PolicyDenied) as exc:
        policy.check(Destination("https", "rebind.test", 443))
    assert exc.value.reason == "blocked_loopback"


def test_names_resolving_into_private_space_are_refused():
    policy = DestinationPolicy(allow_hosts=["internal.test", "metadata.test"])
    with pytest.raises(PolicyDenied) as exc:
        policy.check(Destination("https", "internal.test", 443))
    assert exc.value.reason == "blocked_private_network"
    with pytest.raises(PolicyDenied) as exc:
        policy.check(Destination("https", "metadata.test", 443))
    assert exc.value.reason == "blocked_metadata_endpoint"


def test_unresolvable_names_fail_closed():
    policy = DestinationPolicy(allow_hosts=["*"])
    with pytest.raises(PolicyDenied) as exc:
        policy.check(Destination("https", "nowhere.test", 443))
    assert exc.value.reason == "dns_resolution_failed"


def test_resolve_and_validate_returns_addresses():
    assert [str(ip) for ip in resolve_and_validate("api.github.com")] == ["140.82.121.6"]


def test_dns_answers_pointing_inside_are_dropped():
    kept, dropped = filter_dns_answers(
        [
            ("api.example.com", "93.184.216.34"),
            ("api.example.com", "127.0.0.1"),
            ("api.example.com", "192.168.1.5"),
            ("api.example.com", "169.254.169.254"),
        ]
    )
    assert kept == [("api.example.com", "93.184.216.34")]
    assert len(dropped) == 3


def test_redirect_within_origin_keeps_credentials(policy):
    current = Destination("https", "api.example.com", 443)
    assert check_redirect(current, Destination("https", "api.example.com", 443), policy) is True


def test_redirect_across_origins_drops_credentials(policy):
    current = Destination("https", "api.example.com", 443)
    other = Destination("https", "example.com", 443)
    assert check_redirect(current, other, policy) is False


def test_redirect_to_a_blocked_destination_raises(policy):
    current = Destination("https", "api.example.com", 443)
    with pytest.raises(PolicyDenied):
        check_redirect(current, Destination("https", "169.254.169.254", 443), policy)
