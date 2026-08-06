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


def test_capability_in_the_body_is_refused(addon, broker_stub):
    flow = http_flow(method=b"POST", content=f'{{"key":"{TOKEN}"}}'.encode())
    addon.request(flow)
    assert flow.response.headers["X-Asbx-Reason"] == "capability_misplaced"
    assert broker_stub.requests == []


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


def test_raw_tcp_can_be_allowed_explicitly(session, broker_stub):
    session.policy.allow_raw_tcp = True
    addon = SandboxAddon(session, broker_stub, audit=NullAuditLog(session.session_id))
    flow = tflow.ttcpflow()
    addon.tcp_start(flow)
    assert flow.error is None


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


def test_the_addon_does_not_touch_pass_through_responses(addon):
    """Nothing is stripped from an unbrokered response.

    What contains this path is the destination policy, the capability
    bindings, and raw TCP/UDP being refused - none of which is a header. The
    scrub that used to be here removed set-cookie, alt-svc and
    www-authenticate: the first two are covered elsewhere (udp_start kills the
    HTTP/3 attempt alt-svc advertises), and the last broke credentials the
    broker knows nothing about.
    """
    flow = http_flow()
    flow.response = tutils.tresp()
    original = {
        "WWW-Authenticate": 'Bearer realm="https://auth.docker.io/token"',
        "Set-Cookie": "session=abc",
        "Alt-Svc": 'h3=":443"',
        "Content-Type": "text/html",
    }
    for name, value in original.items():
        flow.response.headers[name] = value

    assert not hasattr(addon, "response")
    for name, value in original.items():
        assert flow.response.headers[name] == value


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
