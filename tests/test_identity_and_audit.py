"""Per-session identity (WireGuard, CA) and the redaction rules."""

from __future__ import annotations

import json


from agentsandbox.audit import (
    SENSITIVE_HEADERS,
    AuditLog,
    Redactor,
    fingerprint,
    redactor,
)
from agentsandbox.wireguard import WireGuardIdentity


# -- WireGuard identity ------------------------------------------------------


def test_each_session_gets_a_different_identity():
    a = WireGuardIdentity.generate()
    b = WireGuardIdentity.generate()
    assert a.server_key != b.server_key
    assert a.client_key != b.client_key
    # A config from an old session authenticates to nothing in a new one.
    assert a.client_public != b.client_public


def test_mitm_conf_is_the_shape_mitmproxy_expects(tmp_path):
    identity = WireGuardIdentity.generate(listen_port=51899)
    path = identity.write_mitm_conf(tmp_path / "wg.json")
    data = json.loads(path.read_text())
    assert set(data) == {"server_key", "client_key"}
    assert path.stat().st_mode & 0o077 == 0


def test_guest_config_routes_everything_through_the_tunnel(tmp_path):
    identity = WireGuardIdentity.generate(listen_port=51820)
    config = identity.guest_config(endpoint_host="192.168.127.1")

    assert "AllowedIPs = 0.0.0.0/0" in config
    assert "Endpoint = 192.168.127.1:51820" in config
    assert "DNS = 10.0.0.53" in config
    # The guest gets its own private key and the server's *public* key only.
    assert identity.client_key in config
    assert identity.server_key not in config
    assert identity.server_public in config
    # No IPv6 address or route: there is no tunnelled IPv6 path.
    assert "::" not in config


def test_guest_config_file_is_owner_only(tmp_path):
    identity = WireGuardIdentity.generate()
    path = identity.write_guest_config(tmp_path / "wg0.conf")
    assert path.stat().st_mode & 0o077 == 0


# -- redaction ---------------------------------------------------------------


def test_registered_secrets_are_scrubbed_anywhere_they_appear():
    r = Redactor()
    r.register_secret("ghp_realsecret0123456789")
    assert "ghp_realsecret0123456789" not in r.text("token=ghp_realsecret0123456789 rest")
    assert "[redacted]" in r.text("token=ghp_realsecret0123456789")


def test_credential_shapes_are_scrubbed_even_if_never_registered():
    r = Redactor()
    for value in (
        "cap_v1_abcdefghijklmnopqrstuvwx",
        "ghp_abcdefghijklmnopqrstuvwxyz0123",
        "sk-abcdefghijklmnopqrstuvwx",
        "xoxb-1234567890-abcdefghij",
        "AKIAIOSFODNN7EXAMPLE",
        "Bearer abcdefghijklmnopqrst",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdef",
    ):
        assert value not in r.text(f"value: {value}"), value


def test_sensitive_headers_are_dropped_by_name_not_by_pattern():
    r = Redactor()
    headers = r.headers(
        [
            ("Authorization", "Bearer x"),
            ("Cookie", "session=abc"),
            ("X-Api-Key", "anything at all"),
            ("Accept", "application/json"),
        ]
    )
    assert ["Accept", "application/json"] in headers
    assert all(value == "[redacted]" for name, value in headers if name != "Accept")


def test_every_sensitive_header_name_is_lowercase():
    """The lookup is done on ``name.lower()``; a capitalised entry would miss."""
    assert all(name == name.lower() for name in SENSITIVE_HEADERS)


def test_long_values_are_truncated():
    r = Redactor()
    out = r.text("a" * 5000)
    assert len(out) < 700
    assert "[+" in out


def test_nested_structures_are_scrubbed():
    r = Redactor()
    r.register_secret("supersecretvalue")
    out = r.value({"headers": {"Authorization": "Bearer supersecretvalue"}, "list": ["supersecretvalue"]})
    assert "supersecretvalue" not in json.dumps(out)


def test_fingerprint_is_stable_and_not_reversible():
    assert fingerprint("abc") == fingerprint("abc")
    assert "abc" not in fingerprint("abc")
    assert fingerprint("abc") != fingerprint("abd")


# -- audit log ---------------------------------------------------------------


def test_audit_records_are_scrubbed_on_the_way_in(tmp_path):
    redactor.register_secret("ghp_thisistherealsecret1")
    log = AuditLog(tmp_path / "audit.jsonl", "session-1")
    log.emit(
        "broker.request",
        headers=[("Authorization", "Bearer ghp_thisistherealsecret1")],
        note="token ghp_thisistherealsecret1 used",
    )
    raw = (tmp_path / "audit.jsonl").read_text()
    assert "ghp_thisistherealsecret1" not in raw
    assert "[redacted]" in raw


def test_audit_log_is_owner_only_and_append_only(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl", "session-1")
    log.emit("a")
    log.emit("b")
    assert (tmp_path / "audit.jsonl").stat().st_mode & 0o077 == 0
    assert [r["event"] for r in log.read()] == ["a", "b"]


def test_audit_bodies_are_never_stored(tmp_path):
    """The spec forbids flow dumps; the audit log records sizes, not content."""
    log = AuditLog(tmp_path / "audit.jsonl", "s")
    record = log.emit("broker.request", body_bytes=4096)
    assert record["body_bytes"] == 4096
    assert "body" not in record


def test_the_guest_never_learns_the_host_side_wireguard_port():
    """The guest dials the gateway's virtual endpoint, not mitmproxy's port.

    Regression: the guest config used to carry the host's randomly chosen
    listen port, so every handshake was dropped by the L2 gateway (which only
    accepts the virtual endpoint) and the tunnel silently never came up.
    """
    identity = WireGuardIdentity.generate(listen_host="127.0.0.1", listen_port=53452)
    config = identity.guest_config(endpoint_host="192.168.127.1", endpoint_port=51820)

    assert "Endpoint = 192.168.127.1:51820" in config
    assert "53452" not in config
    assert "127.0.0.1" not in config
