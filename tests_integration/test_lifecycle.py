"""A real guest, booted under vfkit: tunnel, gateway, and policy enforcement
exercised against an actual VM rather than the pure-Python model of one.
"""

from __future__ import annotations

from helpers import asbx, audit_events, ssh_run

# Tunnel readiness (real traffic relayed, not just the guest's own bootstrap
# script claiming success) is verified once, in the booted_box/fresh_box
# fixtures themselves - see conftest.py's _boot_box. A box that never gets a
# working tunnel fails there, at setup, with a clear reason, rather than each
# test below hanging on a dead tunnel with a confusing ssh-timeout instead.


def test_an_allowed_host_is_reachable_from_inside_the_guest(booted_box):
    box_name, _ = booted_box
    result = ssh_run(box_name, "curl -sS -o /dev/null -w '%{http_code}' https://api.github.com/rate_limit")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "200"


def test_a_non_allowlisted_host_cannot_be_resolved_from_inside_the_guest(fresh_box):
    """The session's own destination policy, not just the broker's - a host
    never mentioned in --allow should fail to resolve at all, the same way
    it does in the unit-tested addon, but from a real guest's resolver."""
    box_name, _ = fresh_box(allow=["api.github.com"])
    result = ssh_run(box_name, "getent hosts example.com")
    assert result.returncode != 0, "example.com resolved despite not being in --allow"


def test_guest_diagnostics_survive_teardown(fresh_box):
    """`box diag` reads from the host-side virtio-fs share and the session's
    own logs - both should still be there after the guest itself is gone.
    Uses its own box (not the shared `booted_box`) since it deliberately
    stops it mid-test; `fresh_box`'s own teardown tolerates a box that's
    already stopped."""
    box_name, session = fresh_box(allow=["api.github.com"])
    asbx("box", "stop", box_name)
    result = asbx("box", "diag", session.session_id)
    assert "guest console" in result.stdout
    assert "[asbx-bootstrap] ready" in result.stdout


def test_net_forward_is_audited_for_unbrokered_traffic(booted_box):
    """A plain request to an allowed host with no capability involved still
    shows up in the audit trail as net.forward - the same event the unit
    tests check for, now emitted by a real running broker/addon pair."""
    box_name, session = booted_box
    ssh_run(box_name, "curl -sS -o /dev/null https://api.github.com/rate_limit")
    events = audit_events(session, "net.forward")
    assert any(e.get("host") == "api.github.com" for e in events)
