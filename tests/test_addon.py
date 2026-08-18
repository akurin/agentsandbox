"""The mitmproxy addon: policy at the network boundary.

Flows are built with mitmproxy's own test helpers, so the addon is exercised
through the same objects it will see in production.
"""

from __future__ import annotations

import pytest
from mitmproxy.net.dns import response_codes
from mitmproxy.test import tflow, tutils

from agentsandbox.audit import NullAuditLog
from agentsandbox.broker.core import BrokerResponse
from agentsandbox.errors import BrokerError
from agentsandbox.proxy.addon import SandboxAddon


class FakeBroker:
    """Captures what the addon delegated, and answers with a canned response."""

    def __init__(self, response: BrokerResponse | None = None, error: Exception | None = None):
        self.response = response or BrokerResponse(
            200, [("Content-Type", "application/json")], b'{"ok":true}', "allow", "", "cap-1"
        )
        self.error = error
        self.requests = []

    def call(self, request):
        if self.error:
            raise self.error
        self.requests.append(request)
        return self.response


@pytest.fixture
def broker_stub():
    return FakeBroker()


@pytest.fixture
def addon(session, broker_stub):
    return SandboxAddon(session, broker_stub, audit=NullAuditLog(session.session_id))


def http_flow(**kwargs):
    params = {
        "method": b"GET",
        "scheme": b"https",
        "host": "api.github.com",
        "port": 443,
        "path": b"/repos/acme/api",
        "http_version": b"HTTP/2.0",
    }
    params.update(kwargs)
    headers = params.pop("headers", None)
    content = params.pop("content", b"")
    request = tutils.treq(**params)
    if headers is not None:
        request.headers.clear()
        for name, value in headers:
            request.headers.add(name.encode(), value.encode())
    request.content = content
    return tflow.tflow(req=request)


TOKEN = "cap_v1_abcdefghijklmnopqrstuvwxyz01"


# -- allowlist ---------------------------------------------------------------


def test_allowlisted_host_passes_through(addon, broker_stub):
    flow = http_flow()
    addon.request(flow)
    assert flow.response is None  # left for mitmproxy to forward
    assert broker_stub.requests == []


def test_host_outside_the_allowlist_is_killed(addon):
    flow = http_flow(host="evil.test")
    addon.request(flow)
    assert flow.response.status_code == 403
    assert flow.response.headers["X-Asbx-Reason"] == "host_not_allowlisted"


def test_the_mac_itself_is_unreachable(addon):
    for host in ("127.0.0.1", "localhost", "host.docker.internal", "192.168.1.10"):
        flow = http_flow(host=host)
        addon.request(flow)
        assert flow.response.status_code == 403, host


def test_cloud_metadata_is_unreachable(addon):
    flow = http_flow(host="169.254.169.254", scheme=b"http", port=80)
    addon.request(flow)
    assert flow.response.status_code == 403
    assert flow.response.headers["X-Asbx-Reason"] == "blocked_metadata_endpoint"


def test_plaintext_http_is_allowed_by_default(addon):
    flow = http_flow(scheme=b"http", port=80)
    addon.request(flow)
    assert flow.response is None  # forwarded, not killed

def test_plaintext_http_can_be_refused_explicitly(session, broker_stub):
    session.policy.allow_plaintext_http = False
    addon = SandboxAddon(session, broker_stub, audit=NullAuditLog(session.session_id))
    flow = http_flow(scheme=b"http", port=80)
    addon.request(flow)
    assert flow.response.headers["X-Asbx-Reason"] == "plaintext_http_denied"


# -- capability detection ----------------------------------------------------


def test_capability_in_a_header_is_brokered(addon, broker_stub):
    flow = http_flow(headers=[("Host", "api.github.com"), ("Authorization", f"Bearer {TOKEN}")])
    addon.request(flow)

    assert len(broker_stub.requests) == 1
    brokered = broker_stub.requests[0]
    assert brokered.capability == TOKEN
    assert brokered.host == "api.github.com"
    assert flow.response.status_code == 200
    assert flow.response.content == b'{"ok":true}'


def test_capability_in_a_custom_header_is_brokered(addon, broker_stub):
    flow = http_flow(headers=[("Host", "api.github.com"), ("X-Api-Key", TOKEN)])
    addon.request(flow)
    assert broker_stub.requests[0].capability == TOKEN


def test_capability_in_the_url_is_refused_before_it_leaves(addon, broker_stub):
    flow = http_flow(path=f"/repos/acme/api?token={TOKEN}".encode())
    addon.request(flow)
    assert flow.response.status_code == 403
    assert flow.response.headers["X-Asbx-Reason"] == "capability_misplaced"
    assert broker_stub.requests == []


def test_capability_in_the_body_is_routed_to_the_broker(addon, broker_stub):
    """Unlike the URL or a cookie, a body-carried placeholder isn't
    automatically a leak - only the broker knows whether the capability
    behind it was actually issued with injection.kind "body", so the addon
    routes it there rather than denying outright. A capability that turns
    out *not* to be body-kind is refused by the broker itself
    (BrokerCore._authorize / _reject_leaked_placeholders), covered at that
    layer in test_broker.py."""
    flow = http_flow(method=b"POST", content=f'{{"key":"{TOKEN}"}}'.encode())
    addon.request(flow)
    assert len(broker_stub.requests) == 1
    assert broker_stub.requests[0].capability == TOKEN
    assert flow.response.status_code == 200


def test_all_placeholders_in_a_body_are_forwarded_to_the_broker(addon, broker_stub):
    """The Travis-style case: one x-www-form-urlencoded POST needing four
    separate secrets substituted into four separate fields. Every
    placeholder found in the body must reach the broker, not just the
    first - the broker (not the addon) decides whether each one is
    actually authorized for this request."""
    token2 = "cap_v1_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    token3 = "cap_v1_cccccccccccccccccccccccccccccc"
    token4 = "cap_v1_dddddddddddddddddddddddddddddd"
    flow = http_flow(
        method=b"POST",
        content=(
            f"client_id={TOKEN}&client_secret={token2}&username={token3}&password={token4}"
        ).encode(),
    )
    addon.request(flow)
    assert len(broker_stub.requests) == 1
    brokered = broker_stub.requests[0]
    assert brokered.capability == TOKEN
    assert brokered.extra_capabilities == [token2, token3, token4]


def test_a_repeated_placeholder_in_the_body_is_only_listed_once(addon, broker_stub):
    """The same secret embedded twice in one body needs one substitution,
    not a second, redundant resolve/authorize round trip."""
    flow = http_flow(
        method=b"POST",
        content=f'{{"a":"{TOKEN}","b":"{TOKEN}"}}'.encode(),
    )
    addon.request(flow)
    assert broker_stub.requests[0].capability == TOKEN
    assert broker_stub.requests[0].extra_capabilities == []


def test_a_body_placeholder_denied_for_the_wrong_host_is_forwarded_unbrokered(addon, broker_stub):
    """A capability's own placeholder showing up in a body headed somewhere
    its scope doesn't cover was never going to be substituted either way -
    `check_destination` runs before any secret is fetched - so blocking the
    whole request protects nothing. Falling back to an ordinary forward
    (still subject to the session's own allowlist) is what keeps a
    placeholder merely echoed into an unrelated request - exactly what
    conversation history relayed back to a model provider legitimately
    does - from breaking traffic that was never a leak."""
    broker_stub.response = BrokerResponse(403, [], b"", "deny", "host_not_permitted", "")
    flow = http_flow(method=b"POST", content=f'{{"key":"{TOKEN}"}}'.encode())
    addon.request(flow)
    assert flow.response is None  # left for mitmproxy to fetch for real, same as an ordinary forward
    assert flow.metadata.get("asbx_plain_forward") is True


def test_a_body_placeholder_that_does_not_resolve_is_forwarded_unbrokered(addon, broker_stub):
    """Same reasoning, the other denial reason that never risked a secret:
    an unknown/malformed placeholder can never be substituted for anything,
    so there is nothing to protect by blocking it."""
    broker_stub.response = BrokerResponse(403, [], b"", "deny", "unknown_capability", "")
    flow = http_flow(method=b"POST", content=f'{{"key":"{TOKEN}"}}'.encode())
    addon.request(flow)
    assert flow.response is None
    assert flow.metadata.get("asbx_plain_forward") is True


def test_a_body_placeholder_denied_as_expired_is_still_blocked(addon, broker_stub):
    """Contrast case: a denial reason that implies the capability *did*
    resolve and *did* match this destination - just too late - still gets a
    plain, surfaced denial, not a silent downgrade. Silently forwarding an
    expired-but-otherwise-correct capability's placeholder would hide a
    genuinely actionable signal (renew it) behind a confusing upstream
    401/403 instead."""
    broker_stub.response = BrokerResponse(403, [], b'{"error":"x"}', "deny", "capability_expired", "")
    flow = http_flow(method=b"POST", content=f'{{"key":"{TOKEN}"}}'.encode())
    addon.request(flow)
    assert flow.response.status_code == 403
    assert flow.metadata.get("asbx_plain_forward") is not True


def test_capability_in_a_cookie_is_refused(addon, broker_stub):
    flow = http_flow(headers=[("Host", "api.github.com"), ("Cookie", f"auth={TOKEN}")])
    addon.request(flow)
    assert flow.response.headers["X-Asbx-Reason"] == "capability_misplaced"
    assert broker_stub.requests == []


# -- aws autosign -------------------------------------------------------------


DUMMY_ACCESS_KEY_ID = "AKIADUMMYSESSIONMARKER1"


def _autosign_header(access_key_id: str) -> str:
    return (
        f"AWS4-HMAC-SHA256 Credential={access_key_id}/20260101/us-east-1/sts/aws4_request, "
        "SignedHeaders=host;x-amz-date, Signature=deadbeef"
    )


@pytest.fixture
def autosign_session(session):
    from agentsandbox.capabilities import AwsAutosignSpec, SecretRef

    session.aws_autosign = AwsAutosignSpec(
        signing_secret=SecretRef(backend="file", service="/tmp/cred.json"),
        access_key_id=DUMMY_ACCESS_KEY_ID,
    )
    return session


def test_dummy_signed_aws_request_is_routed_for_autosign(autosign_session, broker_stub):
    addon = SandboxAddon(autosign_session, broker_stub, audit=NullAuditLog(autosign_session.session_id))
    flow = http_flow(
        method=b"POST",
        headers=[("Host", "api.github.com"), ("Authorization", _autosign_header(DUMMY_ACCESS_KEY_ID))],
    )
    addon.request(flow)
    assert len(broker_stub.requests) == 1
    brokered = broker_stub.requests[0]
    assert brokered.aws_autosign is True
    assert brokered.capability == ""


def test_a_session_without_aws_autosign_leaves_the_same_request_alone(session, broker_stub):
    """A session that never declared `aws_autosign` has no marker to compare
    against - a request that would have matched in another session just
    forwards or gets killed like any other unbrokered traffic."""
    addon = SandboxAddon(session, broker_stub, audit=NullAuditLog(session.session_id))
    flow = http_flow(
        method=b"POST",
        headers=[("Host", "api.github.com"), ("Authorization", _autosign_header(DUMMY_ACCESS_KEY_ID))],
    )
    addon.request(flow)
    assert flow.response is None  # left for mitmproxy to forward
    assert broker_stub.requests == []


def test_a_body_placeholder_on_a_dummy_signed_request_is_flagged_for_autosign(
    autosign_session, broker_stub
):
    """The exact shape a `cdk deploy` asset upload takes: dummy-signed by the
    guest's own AWS credential, with a body-kind capability's placeholder
    embedded in the content. The broker needs both pieces of information to
    decide - so the addon threads `aws_autosign` through `_broker_body`
    exactly the way `_broker_aws_autosign` already does for the pure case."""
    addon = SandboxAddon(autosign_session, broker_stub, audit=NullAuditLog(autosign_session.session_id))
    flow = http_flow(
        method=b"PUT",
        headers=[("Host", "api.github.com"), ("Authorization", _autosign_header(DUMMY_ACCESS_KEY_ID))],
        content=f'{{"key":"{TOKEN}"}}'.encode(),
    )
    addon.request(flow)
    assert len(broker_stub.requests) == 1
    brokered = broker_stub.requests[0]
    assert brokered.capability == TOKEN
    assert brokered.aws_autosign is True


def test_a_different_access_key_is_not_treated_as_this_sessions_autosign_marker(
    autosign_session, broker_stub
):
    addon = SandboxAddon(autosign_session, broker_stub, audit=NullAuditLog(autosign_session.session_id))
    flow = http_flow(
        method=b"POST",
        headers=[("Host", "api.github.com"), ("Authorization", _autosign_header("AKIASOMEOTHERKEY0000"))],
    )
    addon.request(flow)
    assert flow.response is None
    assert broker_stub.requests == []


def test_a_broker_that_is_down_fails_closed(session):
    addon = SandboxAddon(
        session,
        FakeBroker(error=BrokerError("broker unavailable")),
        audit=NullAuditLog(session.session_id),
    )
    flow = http_flow(headers=[("Host", "api.github.com"), ("Authorization", f"Bearer {TOKEN}")])
    addon.request(flow)
    assert flow.response.status_code == 403
    assert flow.response.headers["X-Asbx-Reason"] == "broker_unavailable"


def test_brokered_denials_reach_the_client_as_the_brokers_answer(session):
    denial = BrokerResponse(
        403, [("X-Asbx-Reason", "method_not_permitted")], b"{}", "deny", "method_not_permitted"
    )
    addon = SandboxAddon(session, FakeBroker(denial), audit=NullAuditLog(session.session_id))
    flow = http_flow(headers=[("Host", "api.github.com"), ("Authorization", f"Bearer {TOKEN}")])
    addon.request(flow)
    assert flow.response.status_code == 403
    assert flow.response.headers["X-Asbx-Reason"] == "method_not_permitted"


# -- responses ---------------------------------------------------------------


def test_dns_for_a_blocked_name_is_refused(addon):
    flow = tflow.tdnsflow()
    flow.request.questions[0].name = "printer.local"
    addon.dns_request(flow)
    assert flow.response.response_code == response_codes.REFUSED


def test_dns_for_an_allowed_name_is_left_to_resolve(addon):
    flow = tflow.tdnsflow()
    flow.request.questions[0].name = "api.github.com"
    addon.dns_request(flow)
    assert flow.response is None


def test_dns_answers_pointing_into_blocked_space_are_stripped(addon):
    from mitmproxy import dns

    flow = tflow.tdnsflow(resp=True)
    flow.request.questions[0].name = "api.github.com"
    good = dns.ResourceRecord.A("api.github.com", __import__("ipaddress").IPv4Address("140.82.121.6"))
    bad = dns.ResourceRecord.A("api.github.com", __import__("ipaddress").IPv4Address("127.0.0.1"))
    flow.response.answers = [good, bad]

    addon.dns_response(flow)
    addresses = [str(a.ipv4_address) for a in flow.response.answers]
    assert addresses == ["140.82.121.6"]


# -- non-HTTP ----------------------------------------------------------------


def test_raw_tcp_is_killed_by_default(addon):
    flow = tflow.ttcpflow()
    addon.tcp_start(flow)
    assert flow.killable is False or flow.error is not None


def test_raw_udp_is_killed_by_default(addon):
    flow = tflow.tudpflow()
    addon.udp_start(flow)
    assert flow.killable is False or flow.error is not None


def test_raw_tcp_is_allowed_to_a_pinned_address(session, broker_stub):
    """Pinned by the address the connection actually dials, not a boolean
    switch - `tflow.ttcpflow()`'s own default server address."""
    session.policy.allow_raw_tcp_ips = ["address"]
    addon = SandboxAddon(session, broker_stub, audit=NullAuditLog(session.session_id))
    flow = tflow.ttcpflow()
    addon.tcp_start(flow)
    assert flow.error is None


def test_raw_tcp_to_an_unlisted_address_is_still_killed(session, broker_stub):
    """Pinning one address does not open raw TCP generally - only that one
    address, exactly the gap the old all-or-nothing boolean had."""
    session.policy.allow_raw_tcp_ips = ["some-other-host"]
    addon = SandboxAddon(session, broker_stub, audit=NullAuditLog(session.session_id))
    flow = tflow.ttcpflow()
    addon.tcp_start(flow)
    assert flow.killable is False or flow.error is not None


# -- connection-level enforcement -------------------------------------------


def test_server_connect_blocks_private_addresses(addon):
    from mitmproxy.proxy import server_hooks

    server = tflow.tserver_conn()
    server.address = ("10.1.2.3", 443)
    data = server_hooks.ServerConnectionHookData(server=server, client=tflow.tclient_conn())
    addon.server_connect(data)
    assert "blocked" in (server.error or "")


def test_server_connect_allows_public_addresses(addon):
    from mitmproxy.proxy import server_hooks

    server = tflow.tserver_conn()
    server.address = ("140.82.121.6", 443)
    data = server_hooks.ServerConnectionHookData(server=server, client=tflow.tclient_conn())
    addon.server_connect(data)
    assert server.error is None


def test_server_connect_revalidates_names(addon):
    """Closes the gap between "we checked the name" and "we dialled an IP"."""
    from mitmproxy.proxy import server_hooks

    server = tflow.tserver_conn()
    server.address = ("internal.test", 443)
    data = server_hooks.ServerConnectionHookData(server=server, client=tflow.tclient_conn())
    addon.server_connect(data)
    assert "blocked" in (server.error or "")


# -- the tunnel's own resolver must survive the other hooks ------------------


def test_the_tunnel_resolver_is_not_killed_over_tcp(addon):
    """Resolvers retry over TCP when a UDP answer is truncated."""
    flow = tflow.ttcpflow()
    flow.server_conn.address = ("10.0.0.53", 53)
    addon.tcp_start(flow)
    assert flow.error is None


def test_the_tunnel_resolver_is_not_killed_as_raw_udp(addon):
    """Regression: udp_start killed DNS before dns_request could allow it.

    Symptom in the guest was every lookup timing out while TCP worked fine.
    """
    flow = tflow.tudpflow()
    flow.server_conn.address = ("10.0.0.53", 53)
    addon.udp_start(flow)
    assert flow.error is None


def test_the_tunnel_resolver_is_not_blocked_as_tunnel_network(addon):
    """Regression: server_connect refused 10.0.0.53 as forbidden address space."""
    from mitmproxy.proxy import server_hooks

    server = tflow.tserver_conn()
    server.address = ("10.0.0.53", 53)
    data = server_hooks.ServerConnectionHookData(server=server, client=tflow.tclient_conn())
    addon.server_connect(data)
    assert server.error is None


def test_the_exemption_is_only_that_address_and_port(addon):
    """Everything else in the tunnel network stays unreachable."""
    from mitmproxy.proxy import server_hooks

    for address in [("10.0.0.53", 8080), ("10.0.0.1", 53), ("10.0.0.2", 53)]:
        server = tflow.tserver_conn()
        server.address = address
        data = server_hooks.ServerConnectionHookData(server=server, client=tflow.tclient_conn())
        addon.server_connect(data)
        assert "blocked" in (server.error or ""), address

    flow = tflow.tudpflow()
    flow.server_conn.address = ("10.0.0.53", 5353)
    addon.udp_start(flow)
    assert flow.error is not None

    tcp = tflow.ttcpflow()
    tcp.server_conn.address = ("10.0.0.53", 443)
    addon.tcp_start(tcp)
    assert tcp.error is not None


def test_names_are_still_filtered_on_the_resolver_we_exempted(addon):
    """The exemption is about reachability, not about which names resolve."""
    flow = tflow.tdnsflow()
    flow.request.questions[0].name = "evil.test"
    addon.dns_request(flow)
    assert flow.response.response_code == response_codes.REFUSED


# -- refusing to run in a bypassable configuration ---------------------------


def test_empty_host_filters_are_reported_as_bypasses():
    """`--set ignore_hosts=` yields [''] - an empty regex matching every host.

    Regression: the launcher used to "clear" these options that way, which
    silently turned interception off and routed all UDP through raw layers.
    """
    from agentsandbox.proxy.addon import uninspected_option_problems

    problems = uninspected_option_problems({"ignore_hosts": [""], "allow_hosts": []})
    assert len(problems) == 1
    assert "ignore_hosts" in problems[0]
    assert "matches every host" in problems[0]

    assert uninspected_option_problems({"tcp_hosts": ["example.com"]})
    assert uninspected_option_problems(
        {"ignore_hosts": [], "allow_hosts": [], "tcp_hosts": [], "udp_hosts": []}
    ) == []


def test_running_refuses_to_start_if_tcp_hosts_is_ever_set(session, broker_stub):
    """End to end: `running()` shuts the proxy down if `tcp_hosts` is
    non-empty for any reason, same as the other three options - raw TCP is
    granted through `rawtcp` instead (see launcher.py), never `tcp_hosts`."""
    from unittest.mock import patch

    addon = SandboxAddon(session, broker_stub, audit=NullAuditLog(session.session_id))
    with patch("agentsandbox.proxy.addon.ctx") as mock_ctx:
        mock_ctx.options.ignore_hosts = []
        mock_ctx.options.allow_hosts = []
        mock_ctx.options.tcp_hosts = ["evil.test"]
        mock_ctx.options.udp_hosts = []
        addon.running()
        mock_ctx.master.shutdown.assert_called_once()


# -- basic auth --------------------------------------------------------------


def test_a_placeholder_inside_basic_auth_is_found(addon, broker_stub):
    """`curl -u user:cap_v1_...` must work without rewriting the command.

    Basic auth base64-encodes the credentials, so the placeholder never
    appears literally in the header.
    """
    import base64

    encoded = base64.b64encode(f"developer:{TOKEN}".encode()).decode()
    flow = http_flow(headers=[("Host", "api.github.com"), ("Authorization", f"Basic {encoded}")])
    addon.request(flow)

    assert len(broker_stub.requests) == 1
    assert broker_stub.requests[0].capability == TOKEN


def test_basic_auth_without_a_placeholder_is_left_alone(addon, broker_stub):
    import base64

    encoded = base64.b64encode(b"developer:an-ordinary-password").decode()
    flow = http_flow(headers=[("Host", "api.github.com"), ("Authorization", f"Basic {encoded}")])
    addon.request(flow)
    assert broker_stub.requests == []
    assert flow.response is None  # forwarded, not brokered


def test_malformed_basic_auth_does_not_crash(addon):
    for value in ("Basic", "Basic !!!not-base64!!!", "Basic ", "Bearer something"):
        flow = http_flow(headers=[("Host", "api.github.com"), ("Authorization", value)])
        addon.request(flow)  # must not raise


def test_the_guest_cannot_choose_the_account(addon, broker_stub):
    """The username in the header is ignored; the capability fixes it."""
    import base64

    encoded = base64.b64encode(f"someone-else:{TOKEN}".encode()).decode()
    flow = http_flow(headers=[("Host", "api.github.com"), ("Authorization", f"Basic {encoded}")])
    addon.request(flow)

    brokered = broker_stub.requests[0]
    assert brokered.capability == TOKEN
    # The broker injects from the capability's own InjectionSpec, so nothing
    # about "someone-else" travels with the request.
    assert not any("someone-else" in v for _, v in brokered.headers if "auth" in _.lower())


def test_the_addon_does_not_touch_pass_through_response_headers(addon):
    """Nothing is stripped from an unbrokered response's headers, and a body
    with no registered secret in it passes through unchanged too.

    What contains this path is the destination policy, the capability
    bindings, and raw TCP/UDP being refused - none of which is a header. The
    scrub that used to be here removed set-cookie, alt-svc and
    www-authenticate: the first two are covered elsewhere (udp_start kills the
    HTTP/3 attempt alt-svc advertises), and the last broke credentials the
    broker knows nothing about. `response` exists now, but only to scrub a
    registered secret out of a *body* - see
    test_a_plain_forward_response_with_a_leaked_secret_is_scrubbed below.
    """
    flow = http_flow()
    addon.request(flow)  # marks the flow asbx_plain_forward, as in production
    flow.response = tutils.tresp()
    flow.response.content = b"an ordinary response body"
    original = {
        "WWW-Authenticate": 'Bearer realm="https://auth.docker.io/token"',
        "Set-Cookie": "session=abc",
        "Alt-Svc": 'h3=":443"',
        "Content-Type": "text/html",
    }
    for name, value in original.items():
        flow.response.headers[name] = value

    addon.response(flow)
    for name, value in original.items():
        assert flow.response.headers[name] == value
    assert flow.response.content == b"an ordinary response body"


def test_a_large_plain_forward_response_streams(addon):
    """The fix for a real bug: mitmproxy's default is to buffer a response's
    entire body before relaying any of it, so a plain download's
    time-to-first-byte was matching its *entire* transfer time. `request`
    marks a plain-forwarded flow so `responseheaders` can turn streaming on
    for it - safe for a response too large to scan for a leaked secret
    anyway, since `response` below never sees a streamed body's content.
    """
    flow = http_flow()
    addon.request(flow)  # the plain-forward path: marks the flow
    assert flow.response is None  # left for mitmproxy to fetch for real

    flow.response = tutils.tresp()
    flow.response.headers["content-length"] = str(2 * 1024 * 1024)  # over _BODY_SCAN_LIMIT
    addon.responseheaders(flow)
    assert flow.response.stream is True


def test_a_plain_forward_response_with_no_declared_length_streams(addon):
    """No `Content-Length` means the size is unknown - streamed exactly as
    before, not scanned. Only a response declaring a size this addon knows
    is small enough gets buffered instead."""
    flow = http_flow()
    addon.request(flow)
    flow.response = tutils.tresp()
    del flow.response.headers["content-length"]
    addon.responseheaders(flow)
    assert flow.response.stream is True


def test_a_small_plain_forward_response_is_buffered_not_streamed(addon):
    """A response small enough to scan is left unstreamed (mitmproxy's own
    default) so `response` can inspect its full body for a leaked secret -
    the other half of the fix `test_a_large_plain_forward_response_streams`
    covers."""
    flow = http_flow()
    addon.request(flow)
    flow.response = tutils.tresp()
    flow.response.headers["content-length"] = "26"
    addon.responseheaders(flow)
    assert not flow.response.stream


def test_a_plain_forward_response_with_a_leaked_secret_is_scrubbed(addon):
    """The other half of the fix: an unbrokered response echoing back a real
    secret this session's broker resolved for some *other* request must
    never reach the guest - `scrub_secret` in broker/core.py only covers the
    brokered path, where the secret used and the response come from the same
    call. This is the gap that leaves open otherwise: a debug or
    token-introspection endpoint reflecting a credential resolved earlier in
    the session, reached through an ordinary allowlisted request that never
    carried a capability placeholder at all.
    """
    from agentsandbox.audit import redactor

    redactor.register_secret("sekrit-value-123456")

    flow = http_flow()
    addon.request(flow)
    flow.response = tutils.tresp()
    flow.response.content = b'{"echo": "Bearer sekrit-value-123456"}'
    flow.response.headers["content-length"] = str(len(flow.response.content))

    addon.response(flow)
    assert b"sekrit-value-123456" not in flow.response.content
    assert b"[redacted]" in flow.response.content
    assert flow.response.headers["content-length"] == str(len(flow.response.content))


def test_a_plain_forward_response_with_no_secret_is_untouched(addon):
    """The common case: nothing registered, nothing to find, body and
    Content-Length both left exactly as they arrived."""
    from agentsandbox.audit import redactor

    redactor.register_secret("sekrit-value-123456")

    flow = http_flow()
    addon.request(flow)
    flow.response = tutils.tresp()
    flow.response.content = b'{"ok": true}'
    original_length = flow.response.headers["content-length"]

    addon.response(flow)
    assert flow.response.content == b'{"ok": true}'
    assert flow.response.headers["content-length"] == original_length


def test_a_brokered_response_is_never_streamed(addon, broker_stub):
    """A brokered response is a synthetic one this addon built from bytes the
    broker already has in hand, not a real upstream connection mitmproxy is
    mid-fetch on - streaming it would be nonsensical, and `request` never
    marks this flow as a plain forward in the first place."""
    flow = http_flow(headers=[("Host", "api.github.com"), ("Authorization", f"Bearer {TOKEN}")])
    addon.request(flow)
    assert flow.response is not None  # the broker already answered

    addon.responseheaders(flow)
    assert not flow.response.stream


def test_a_killed_flow_is_never_streamed(addon):
    """A denied flow's response is this addon's own synthetic 403, never a
    real upstream fetch - same reasoning as the brokered case above."""
    flow = http_flow(host="evil.test")
    addon.request(flow)
    assert flow.response.status_code == 403

    addon.responseheaders(flow)
    assert not flow.response.stream


def test_brokered_responses_are_still_sanitised():
    """The exception, and the reason `response` could go.

    On a brokered flow the broker authenticated with a real credential. A
    session cookie coming back is bearer-equivalent: the guest could spend it
    on any path or method, outside everything the capability restricts. That
    one is an escalation, not an inconvenience.
    """
    from agentsandbox.broker.upstream import sanitize_response_headers

    kept = sanitize_response_headers(
        [
            ("Set-Cookie", "session=abc"),
            ("Authentication-Info", "nextnonce=x"),
            ("WWW-Authenticate", 'Bearer realm="https://auth.example.com/token"'),
            ("Content-Type", "application/json"),
        ]
    )
    names = {k.lower() for k, _ in kept}
    assert "set-cookie" not in names
    assert "authentication-info" not in names
    assert "www-authenticate" in names  # a challenge, not a credential
    assert "content-type" in names
