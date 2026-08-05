"""Redirect handling: "redirects cannot move credentials to another origin"."""

from __future__ import annotations

import pytest

from agentsandbox.broker.upstream import (
    UpstreamExecutor,
    UpstreamResponse,
    _resolve_location,
    clean_headers,
    sanitize_response_headers,
)
from agentsandbox.errors import UpstreamError
from agentsandbox.netpolicy import Destination, DestinationPolicy

CREDENTIAL = [("Authorization", "Bearer real-secret")]


class ScriptedExecutor(UpstreamExecutor):
    """Replays a scripted chain of responses, recording every hop."""

    def __init__(self, policy, script):
        super().__init__(policy)
        self.script = list(script)
        self.hops: list[dict] = []

    def _round_trip(self, dest, method, target, headers, body, max_bytes):
        self.hops.append(
            {
                "dest": dest,
                "method": method,
                "target": target,
                "headers": list(headers),
                "carried_credential": any(k == "Authorization" for k, _ in headers),
            }
        )
        return self.script.pop(0)


def redirect(location: str, status: int = 302) -> UpstreamResponse:
    return UpstreamResponse(status_code=status, headers=[("Location", location)], body=b"")


def ok(body: bytes = b"done") -> UpstreamResponse:
    return UpstreamResponse(status_code=200, headers=[], body=body)


@pytest.fixture
def policy():
    return DestinationPolicy(allow_hosts=["api.example.com", "example.com", "other.example.net"])


def test_same_origin_redirect_keeps_the_credential(policy):
    executor = ScriptedExecutor(policy, [redirect("/v2/thing"), ok()])
    result = executor.execute(
        Destination("https", "api.example.com", 443),
        "GET",
        "/v1/thing",
        [],
        b"",
        CREDENTIAL,
        1000,
    )
    assert result.status_code == 200
    assert [hop["carried_credential"] for hop in executor.hops] == [True, True]


def test_cross_origin_redirect_drops_the_credential(policy):
    executor = ScriptedExecutor(policy, [redirect("https://other.example.net/steal"), ok()])
    executor.execute(
        Destination("https", "api.example.com", 443), "GET", "/v1", [], b"", CREDENTIAL, 1000
    )
    assert [hop["carried_credential"] for hop in executor.hops] == [True, False]
    assert executor.hops[1]["dest"].host == "other.example.net"


def test_credential_is_not_reattached_when_a_redirect_returns_home(policy):
    """Off-origin then back again must not resurrect the credential."""
    executor = ScriptedExecutor(
        policy,
        [
            redirect("https://other.example.net/hop"),
            redirect("https://api.example.com/back"),
            ok(),
        ],
    )
    executor.execute(
        Destination("https", "api.example.com", 443), "GET", "/v1", [], b"", CREDENTIAL, 1000
    )
    assert [hop["carried_credential"] for hop in executor.hops] == [True, False, False]


def test_redirect_to_a_forbidden_destination_is_refused(policy):
    executor = ScriptedExecutor(policy, [redirect("https://169.254.169.254/latest/meta-data")])
    with pytest.raises(UpstreamError) as exc:
        executor.execute(
            Destination("https", "api.example.com", 443), "GET", "/v1", [], b"", CREDENTIAL, 1000
        )
    assert "forbidden destination" in str(exc.value)


def test_redirect_to_a_host_outside_the_allowlist_is_refused(policy):
    executor = ScriptedExecutor(policy, [redirect("https://evil.test/")])
    with pytest.raises(UpstreamError):
        executor.execute(
            Destination("https", "api.example.com", 443), "GET", "/v1", [], b"", CREDENTIAL, 1000
        )


def test_redirect_chain_is_bounded(policy):
    executor = ScriptedExecutor(policy, [redirect("/a"), redirect("/b"), redirect("/c"), ok()])
    executor.max_redirects = 2
    result = executor.execute(
        Destination("https", "api.example.com", 443), "GET", "/v1", [], b"", CREDENTIAL, 1000
    )
    # Stops following and returns the third redirect as-is.
    assert result.status_code == 302
    assert len(executor.hops) == 3


def test_303_downgrades_post_to_get_and_drops_the_body(policy):
    executor = ScriptedExecutor(policy, [redirect("/result", status=303), ok()])
    executor.execute(
        Destination("https", "api.example.com", 443),
        "POST",
        "/submit",
        [],
        b"payload",
        CREDENTIAL,
        1000,
    )
    assert executor.hops[1]["method"] == "GET"


def test_scheme_downgrade_in_a_redirect_keeps_the_credential_dropped(policy):
    """http:// after https:// strips the credential (the broker's rule, not the policy's)."""
    executor = ScriptedExecutor(policy, [redirect("http://api.example.com/v1"), ok()])
    executor.execute(
        Destination("https", "api.example.com", 443), "GET", "/v1", [], b"", CREDENTIAL, 1000
    )
    # Credential was dropped on the downgrade
    assert executor.hops[0]["carried_credential"] is True
    assert executor.hops[1]["carried_credential"] is False


def test_non_http_redirect_schemes_are_refused():
    with pytest.raises(UpstreamError):
        _resolve_location(Destination("https", "api.example.com", 443), "/x", "file:///etc/passwd")


def test_relative_redirects_resolve_against_the_current_url():
    dest, target = _resolve_location(
        Destination("https", "api.example.com", 443), "/v1/a/b", "../c?q=1"
    )
    assert dest.host == "api.example.com"
    assert target == "/v1/c?q=1"


def test_hop_by_hop_headers_are_not_forwarded():
    cleaned = clean_headers(
        [
            ("Connection", "keep-alive"),
            ("Transfer-Encoding", "chunked"),
            ("Host", "spoofed.example.com"),
            ("Content-Length", "5"),
            ("Accept", "application/json"),
        ]
    )
    assert cleaned == [("Accept", "application/json")]


def test_response_sanitisation_drops_gateway_evading_headers():
    kept = sanitize_response_headers(
        [
            ("Set-Cookie", "a=b"),
            ("Alt-Svc", 'h3=":443"'),
            ("Public-Key-Pins", "x"),
            ("Content-Type", "application/json"),
        ]
    )
    assert kept == [("Content-Type", "application/json")]


def test_an_auth_challenge_reaches_the_guest():
    """WWW-Authenticate is a challenge, not a credential.

    It was stripped alongside alt-svc and public-key-pins, which really do let
    a guest route around the gateway. This one only says how to authenticate,
    and the guest can act on it with nothing but a placeholder the broker
    refuses to inject outside a capability's bound host, path and method.

    Removing it broke auth negotiation wholesale. A container registry answers
    /v2/ with 401 plus the realm to fetch a token from; a client that never
    sees the realm cannot proceed, and reports "authentication required"
    against a registry that is answering perfectly well.
    """
    challenge = 'Bearer realm="https://auth.docker.io/token",service="registry.docker.io"'
    kept = sanitize_response_headers([("WWW-Authenticate", challenge)])
    assert kept == [("WWW-Authenticate", challenge)]
