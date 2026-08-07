"""A real capability, issued against a running box and presented from
inside the guest - the one thing IMPLEMENTATION.md's own "Still not
verified" list had been carrying the longest: the broker resolving,
substituting and forwarding a credential for a placeholder a real guest
actually sent, not one built by hand in a unit test.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

import pytest
from helpers import asbx, audit_events, ssh_run

PLACEHOLDER_RE = re.compile(r"cap_v1_[A-Za-z0-9_-]+")


@pytest.fixture
def secret_file():
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write("integration-test-secret-not-a-real-token\n")
        path = Path(fh.name)
    path.chmod(0o600)
    try:
        yield path
    finally:
        path.unlink(missing_ok=True)


def _issue(
    box_name: str, secret_file: Path, *, methods: tuple[str, ...] = ("GET", "HEAD"), path: str = "/rate_limit"
) -> tuple[str, str]:
    """Issue a capability and return (placeholder, cap_id).

    `--method`/`--path` are `action="append"` in the CLI - each value needs
    its own repeated flag, not a comma-joined list after one.
    """
    method_args = [arg for method in methods for arg in ("--method", method)]
    result = asbx(
        "cap", "issue",
        "--box", box_name,
        "--label", "it-broker-check",
        "--host", "api.github.com",
        "--secret", f"file:{secret_file}",
        *method_args,
        "--path", path,
        "--ttl", "120",
    )
    placeholder = PLACEHOLDER_RE.search(result.stdout)
    assert placeholder, f"no placeholder in `cap issue` output:\n{result.stdout}"
    cap_id_match = re.search(r"cap-[0-9a-f]+", result.stdout)
    assert cap_id_match, f"no cap id in `cap issue` output:\n{result.stdout}"
    return placeholder.group(0), cap_id_match.group(0)


def test_a_capability_round_trips_from_inside_the_guest(booted_box, secret_file):
    box_name, session = booted_box
    placeholder, cap_id = _issue(box_name, secret_file)

    script = f"curl -sS -i -H 'Authorization: Bearer {placeholder}' https://api.github.com/rate_limit"
    result = ssh_run(box_name, script)
    assert result.returncode == 0, result.stderr

    # The fake secret is not a real GitHub token, so GitHub correctly
    # refuses it - proof the broker actually substituted *something* and
    # forwarded it, not that the value happened to work.
    assert "HTTP/2 401" in result.stdout or "HTTP/1.1 401" in result.stdout, result.stdout
    assert "x-asbx-decision: allow" in result.stdout.lower()
    assert placeholder not in result.stdout, "the placeholder itself must never reach the guest in the response"

    requests = audit_events(session, "broker.request")
    responses = audit_events(session, "broker.response")
    assert any(r.get("cap_id") == cap_id for r in requests), requests
    assert any(r.get("cap_id") == cap_id and r.get("status") == 401 for r in responses), responses

    asbx("cap", "revoke", cap_id, "--box", box_name, check=False)


def test_a_capability_does_not_authorize_outside_its_own_scope(booted_box, secret_file):
    """Issued for GET /rate_limit only - a DELETE, or a different path,
    must be refused by the real running broker, not just the unit-tested
    one."""
    box_name, session = booted_box
    placeholder, cap_id = _issue(box_name, secret_file, methods=("GET", "HEAD"), path="/rate_limit")

    script = f"curl -sS -i -X DELETE -H 'Authorization: Bearer {placeholder}' https://api.github.com/rate_limit"
    result = ssh_run(box_name, script)
    assert result.returncode == 0, result.stderr
    assert "HTTP/2 403" in result.stdout or "HTTP/1.1 403" in result.stdout, result.stdout
    assert "method_not_permitted" in result.stdout.lower()

    denials = audit_events(session, "broker.denied")
    assert any(d.get("cap_id") == cap_id and d.get("reason") == "method_not_permitted" for d in denials)

    asbx("cap", "revoke", cap_id, "--box", box_name, check=False)
