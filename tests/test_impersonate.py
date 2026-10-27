"""browser_impersonation: the addon marks, the forwarder sends.

curl_cffi's AsyncSession is replaced with a recorder, so these check what
would go on the wire - the pinned address, the headers, no redirect
following - without touching the network.
"""

from __future__ import annotations

import asyncio

import pytest

from agentsandbox.audit import NullAuditLog, redactor
from agentsandbox.netpolicy import BrowserImpersonation
from agentsandbox.proxy import impersonate
from agentsandbox.proxy.addon import SandboxAddon
from agentsandbox.proxy.impersonate import METADATA_KEY, ImpersonatingForwarder
from agentsandbox.session import Session

from test_addon import FakeBroker, http_flow


class FakeHeaders:
    def __init__(self, items):
        self._items = items

    def multi_items(self):
        return list(self._items)


class FakeResponse:
    def __init__(self, status_code=200, headers=(), content=b"ok"):
        self.status_code = status_code
        self.headers = FakeHeaders(headers)
        self.content = content


class FakeAsyncSession:
    instances: list[FakeAsyncSession] = []
    response = FakeResponse()
    error: Exception | None = None

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.calls = []
        FakeAsyncSession.instances.append(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if FakeAsyncSession.error:
            raise FakeAsyncSession.error
        return FakeAsyncSession.response


@pytest.fixture(autouse=True)
def fake_curl(monkeypatch):
    import curl_cffi.requests

    FakeAsyncSession.instances = []
    FakeAsyncSession.response = FakeResponse()
    FakeAsyncSession.error = None
    monkeypatch.setattr(curl_cffi.requests, "AsyncSession", FakeAsyncSession)
    return FakeAsyncSession


@pytest.fixture
def impersonating_session(session) -> Session:
    session.browser_impersonation = BrowserImpersonation(target="chrome", hosts=["*.example.com"])
    return session


@pytest.fixture
def addon(impersonating_session):
    return SandboxAddon(
        impersonating_session, FakeBroker(), audit=NullAuditLog(impersonating_session.session_id)
    )


@pytest.fixture
def forwarder(impersonating_session):
    return ImpersonatingForwarder(NullAuditLog(impersonating_session.session_id))


def run(addon, forwarder, flow):
    addon.request(flow)
    asyncio.run(forwarder.request(flow))
    return flow


def last_call():
    session = FakeAsyncSession.instances[-1]
    return session, session.calls[-1]


# -- which flows take this path ---------------------------------------------


def test_listed_host_is_marked_for_impersonation(addon):
    flow = http_flow(host="api.example.com")
    addon.request(flow)
    assert flow.response is None
    assert flow.metadata[METADATA_KEY] == "chrome"
    # Not streamed by mitmproxy - there is no mitmproxy upstream response.
    assert "asbx_plain_forward" not in flow.metadata


def test_unlisted_host_keeps_mitmproxys_own_connection(addon, forwarder):
    flow = run(addon, forwarder, http_flow(host="api.github.com"))
    assert METADATA_KEY not in flow.metadata
    assert flow.response is None
    assert FakeAsyncSession.instances == []


def test_impersonation_is_not_a_grant(session):
    session.browser_impersonation = BrowserImpersonation(target="chrome", hosts=["evil.test"])
    addon = SandboxAddon(session, FakeBroker(), audit=NullAuditLog(session.session_id))
    flow = http_flow(host="evil.test")
    addon.request(flow)
    assert flow.response.status_code == 403
    assert METADATA_KEY not in flow.metadata


def test_websocket_upgrade_stays_with_mitmproxy(addon):
    flow = http_flow(
        host="api.example.com",
        http_version=b"HTTP/1.1",
        headers=[("Host", "api.example.com"), ("Connection", "Upgrade"), ("Upgrade", "websocket")],
    )
    addon.request(flow)
    assert METADATA_KEY not in flow.metadata


def test_forwarder_ignores_unmarked_flows(forwarder):
    flow = http_flow(host="api.example.com")
    asyncio.run(forwarder.request(flow))
    assert flow.response is None
    assert FakeAsyncSession.instances == []


# -- what goes on the wire --------------------------------------------------


def test_connection_is_pinned_to_the_validated_address(addon, forwarder):
    from curl_cffi import CurlOpt

    run(addon, forwarder, http_flow(host="api.example.com", path=b"/v1/x?q=1"))
    session, (method, url, kwargs) = last_call()
    assert session.kwargs["curl_options"][CurlOpt.RESOLVE] == ["api.example.com:443:93.184.216.34"]
    assert (method, url) == ("GET", "https://api.example.com:443/v1/x?q=1")
    assert kwargs["impersonate"] == "chrome"
    assert kwargs["allow_redirects"] is False
    assert kwargs["discard_cookies"] is True


def test_name_resolving_into_private_space_is_refused(session):
    session.browser_impersonation = BrowserImpersonation(target="chrome", hosts=["*"])
    session.policy.allow_hosts = ["*"]
    forwarder = ImpersonatingForwarder(NullAuditLog(session.session_id))
    flow = http_flow(host="rebind.test")
    # The addon's own check already refuses it; mark it by hand to prove the
    # forwarder re-validates rather than trusting the mark.
    flow.metadata[METADATA_KEY] = "chrome"
    asyncio.run(forwarder.request(flow))
    assert flow.response.status_code == 403
    assert FakeAsyncSession.instances == []


def test_browser_owned_and_hop_headers_are_not_forwarded(addon, forwarder):
    flow = http_flow(
        host="api.example.com",
        headers=[
            ("user-agent", "curl/8.7.1"),
            ("sec-ch-ua", '"Not A;Brand";v="1"'),
            ("accept-encoding", "gzip"),
            ("connection", "keep-alive"),
            ("accept", "application/json"),
            ("authorization", "Bearer firebase-id-token"),
            ("cookie", "a=1"),
            ("cookie", "b=2"),
        ],
    )
    run(addon, forwarder, flow)
    _, (_, _, kwargs) = last_call()
    assert kwargs["headers"] == [
        ("accept", "application/json"),
        ("authorization", "Bearer firebase-id-token"),
        ("cookie", "a=1; b=2"),
    ]


def test_request_body_is_forwarded(addon, forwarder):
    run(addon, forwarder, http_flow(host="api.example.com", method=b"POST", content=b'{"a":1}'))
    _, (method, _, kwargs) = last_call()
    assert method == "POST"
    assert kwargs["data"] == b'{"a":1}'


# -- what the guest gets back -----------------------------------------------


def test_response_is_handed_back_decoded(addon, forwarder, fake_curl):
    fake_curl.response = FakeResponse(
        302,
        [
            ("content-type", "text/html"),
            ("content-encoding", "br"),
            ("content-length", "3"),
            ("location", "/login"),
            ("set-cookie", "a=1"),
            ("set-cookie", "b=2"),
        ],
        b"<html>decoded</html>",
    )
    flow = run(addon, forwarder, http_flow(host="api.example.com"))
    assert flow.response.status_code == 302
    assert flow.response.content == b"<html>decoded</html>"
    assert flow.response.headers["content-length"] == str(len(b"<html>decoded</html>"))
    assert "content-encoding" not in flow.response.headers
    assert flow.response.headers["location"] == "/login"
    assert flow.response.headers.get_all("set-cookie") == ["a=1", "b=2"]


def test_a_known_secret_is_scrubbed_from_the_body(addon, forwarder, fake_curl):
    redactor.register_secret("s3cr3t-value-123")
    fake_curl.response = FakeResponse(200, [], b"token=s3cr3t-value-123")
    flow = run(addon, forwarder, http_flow(host="api.example.com"))
    assert b"s3cr3t-value-123" not in flow.response.content


def test_upstream_failure_is_a_502_not_a_hang(addon, forwarder, fake_curl):
    fake_curl.error = RuntimeError("connection reset")
    flow = run(addon, forwarder, http_flow(host="api.example.com"))
    assert flow.response.status_code == 502
    assert flow.response.headers["X-Asbx-Reason"] == "impersonated_upstream_error"


def test_ip_literal_host_needs_no_pinning(session):
    session.browser_impersonation = BrowserImpersonation(target="chrome", hosts=["93.184.216.34"])
    session.policy.allow_hosts = ["93.184.216.34"]
    addon = SandboxAddon(session, FakeBroker(), audit=NullAuditLog(session.session_id))
    forwarder = ImpersonatingForwarder(NullAuditLog(session.session_id))
    run(addon, forwarder, http_flow(host="93.184.216.34"))
    session_, _ = last_call()
    assert session_.kwargs["curl_options"] == {}


def test_impersonation_survives_a_session_round_trip(impersonating_session):
    impersonating_session.save()
    loaded = Session.load(impersonating_session.session_id)
    assert loaded.browser_impersonation == impersonating_session.browser_impersonation


def test_module_does_not_import_curl_at_load_time():
    """mitmdump loads the addon for every session; one without
    browser_impersonation should not pay for curl_cffi's native library."""
    source = impersonate.__loader__.get_source(impersonate.__name__)
    top_level = [line for line in source.splitlines() if line.startswith(("import ", "from "))]
    assert not any("curl_cffi" in line for line in top_level)
