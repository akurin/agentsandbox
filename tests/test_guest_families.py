"""The small, closed set of facts that differ across guest Linux families."""

from __future__ import annotations

from agentsandbox.vm.guest_families import DEBIAN, FEDORA, get_family


def test_known_families_round_trip_by_name():
    assert get_family("debian") is DEBIAN
    assert get_family("fedora") is FEDORA


def test_an_unknown_family_name_falls_back_to_debian():
    """Every image built before this module existed has no "family" key at
    all - and a typo'd or future name should behave the same way, not
    crash the guest render."""
    assert get_family("arch") is DEBIAN
    assert get_family("") is DEBIAN


def test_families_disagree_on_the_facts_that_actually_vary():
    assert DEBIAN.ca_cert_source_dir != FEDORA.ca_cert_source_dir
    assert DEBIAN.ca_bundle_path != FEDORA.ca_bundle_path
    assert DEBIAN.ssh_service != FEDORA.ssh_service
    assert DEBIAN.nobody_group != FEDORA.nobody_group
    assert DEBIAN.has_ssh_socket and not FEDORA.has_ssh_socket
