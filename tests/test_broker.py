"""The broker: the only place a real credential is ever used.

These tests are the "real credentials never appear inside the VM" and
"a placeholder works only for its approved destination and operation"
acceptance criteria, checked at the component that enforces them.
"""

from __future__ import annotations

import base64
import json


from agentsandbox.audit import AuditLog
from agentsandbox.broker.approvals import AllowAll, ApprovalGate, DenyAll, FileApprovalGate
from agentsandbox.broker.core import BrokerCore, BrokerRequest, BrokerResponse, scrub_secret
from agentsandbox.broker.upstream import UpstreamResponse
from agentsandbox.capabilities import CapabilitySpec, InjectionSpec, SecretRef
from agentsandbox.errors import UpstreamError
from agentsandbox.keychain import SecretResolver, StaticResolver

from helpers import RecordingExecutor, make_request

SECRET = "ghp_realsecretvalue0123456789"


def test_happy_path_injects_the_credential_upstream(broker, executor, github_capability):
    token, cap = github_capability
    response = broker.handle(make_request(token))

    assert response.decision == "allow"
    assert response.status_code == 200
    assert executor.last["credential_headers"] == [("Authorization", f"Bearer {SECRET}")]


def test_the_guests_own_authorization_header_never_goes_upstream(
    broker, executor, github_capability
):
    token, _ = github_capability
    broker.handle(make_request(token))
    forwarded = {k.lower() for k, _ in executor.last["headers"]}
    assert "authorization" not in forwarded


def test_no_placeholder_survives_into_the_upstream_request(broker, executor, github_capability):
    token, _ = github_capability
    broker.handle(
        make_request(
            token,
            headers=[("Authorization", f"Bearer {token}"), ("X-Trace", f"id-{token}")],
        )
    )
    rendered = json.dumps(executor.last["headers"])
    assert token not in rendered


def test_unknown_capability_is_refused(broker):
    response = broker.handle(make_request("cap_v1_thisisnotarealcapability000"))
    assert response.decision == "deny"
    assert response.reason == "unknown_capability"
    assert response.status_code == 403


def test_capability_bound_to_another_session_is_refused(broker, github_capability):
    token, _ = github_capability
    response = broker.handle(make_request(token, session_id="different-session"))
    assert response.reason == "wrong_session"


def test_capability_does_not_work_for_another_host(broker, github_capability):
    token, _ = github_capability
    response = broker.handle(make_request(token, host="api.example.com"))
    assert response.reason == "host_not_permitted"


def test_capability_does_not_work_for_another_method(broker, github_capability):
    token, _ = github_capability
    response = broker.handle(make_request(token, method="DELETE"))
    assert response.reason == "method_not_permitted"


def test_capability_does_not_work_for_another_path(broker, github_capability):
    token, _ = github_capability
    response = broker.handle(make_request(token, target="/user/emails"))
    assert response.reason == "path_not_permitted"


def test_session_policy_applies_before_the_capability(session, store, executor, resolver):
    """A capability cannot widen the session's own allowlist."""
    from agentsandbox.netpolicy import DestinationPolicy

    narrow = DestinationPolicy(allow_hosts=["example.com"])
    core = BrokerCore(
        session.session_id, store, narrow, resolver, approvals=AllowAll(), executor=executor
    )
    token, _ = store.issue(
        CapabilitySpec(
            provider="github",
            hosts=["api.github.com"],
            secret=SecretRef(service="github-token"),
        )
    )
    response = core.handle(make_request(token))
    assert response.reason == "host_not_allowlisted"
    assert executor.calls == []


def test_capability_in_the_url_is_refused(broker, github_capability):
    token, _ = github_capability
    response = broker.handle(
        make_request(token, target=f"/repos/acme/api/issues?access_token={token}")
    )
    assert response.reason == "capability_in_url"


def test_capability_in_the_body_is_refused(broker, github_capability):
    token, _ = github_capability
    response = broker.handle(
        make_request(token, method="GET", body=json.dumps({"token": token}).encode())
    )
    assert response.reason == "capability_in_body"


def test_expired_capability_is_refused(broker, store):
    token, cap = store.issue(
        CapabilitySpec(
            provider="github",
            hosts=["api.github.com"],
            secret=SecretRef(service="github-token"),
            ttl_seconds=-1,
        )
    )
    assert broker.handle(make_request(token)).reason == "capability_expired"


def test_revoked_capability_is_refused_immediately(broker, store, github_capability):
    token, cap = github_capability
    store.revoke(cap.cap_id)
    assert broker.handle(make_request(token)).reason == "capability_revoked"


def test_request_budget_is_enforced_across_calls(session, store, executor, resolver):
    core = BrokerCore(
        session.session_id, store, session.policy, resolver, approvals=AllowAll(), executor=executor
    )
    token, _ = store.issue(
        CapabilitySpec(
            provider="github",
            hosts=["api.github.com"],
            secret=SecretRef(service="github-token"),
            max_requests=2,
        )
    )
    assert core.handle(make_request(token)).decision == "allow"
    assert core.handle(make_request(token)).decision == "allow"
    third = core.handle(make_request(token))
    assert third.reason == "request_budget_exhausted"
    assert len(executor.calls) == 2


def test_oversized_response_is_refused_not_truncated(session, store, resolver):
    executor = RecordingExecutor(
        UpstreamResponse(status_code=200, headers=[], body=b"x" * 100, truncated=True)
    )
    core = BrokerCore(
        session.session_id, store, session.policy, resolver, approvals=AllowAll(), executor=executor
    )
    token, _ = store.issue(
        CapabilitySpec(
            provider="github",
            hosts=["api.github.com"],
            secret=SecretRef(service="github-token"),
            max_response_bytes=50,
        )
    )
    response = core.handle(make_request(token))
    assert response.reason == "response_too_large"
    assert b"x" * 100 not in response.body


def test_credential_echoed_by_upstream_is_scrubbed_from_the_response(session, store, resolver):
    executor = RecordingExecutor(
        UpstreamResponse(
            status_code=200,
            headers=[("Content-Type", "application/json")],
            body=json.dumps({"token": SECRET, "user": "acme-bot"}).encode(),
        )
    )
    core = BrokerCore(
        session.session_id, store, session.policy, resolver, approvals=AllowAll(), executor=executor
    )
    token, _ = store.issue(
        CapabilitySpec(
            provider="github",
            hosts=["api.github.com"],
            secret=SecretRef(service="github-token"),
        )
    )
    response = core.handle(make_request(token))
    assert SECRET.encode() not in response.body
    assert b"[redacted]" in response.body
    assert b"acme-bot" in response.body


def test_credential_bearing_response_headers_are_stripped(session, store, resolver):
    executor = RecordingExecutor(
        UpstreamResponse(
            status_code=200,
            headers=[
                ("Set-Cookie", "session=abc; HttpOnly"),
                ("WWW-Authenticate", "Bearer realm=x"),
                ("Alt-Svc", 'h3=":443"'),
                ("X-Echo", f"token {SECRET}"),
                ("Content-Type", "text/plain"),
            ],
            body=b"ok",
        )
    )
    core = BrokerCore(
        session.session_id, store, session.policy, resolver, approvals=AllowAll(), executor=executor
    )
    token, _ = store.issue(
        CapabilitySpec(
            provider="github", hosts=["api.github.com"], secret=SecretRef(service="github-token")
        )
    )
    names = {k.lower() for k, _ in core.handle(make_request(token)).headers}
    assert "set-cookie" not in names
    assert "www-authenticate" not in names
    assert "alt-svc" not in names
    assert "x-echo" not in names  # dropped: its value contained the credential
    assert "content-type" in names


def test_identity_encoding_is_forced_so_bodies_stay_scannable(broker, executor, github_capability):
    token, _ = github_capability
    broker.handle(make_request(token, headers=[("Accept-Encoding", "gzip, br")]))
    encodings = [v for k, v in executor.last["headers"] if k.lower() == "accept-encoding"]
    assert encodings == ["identity"]


def test_mutating_operations_are_denied_without_an_approval_channel(session, store, executor, resolver):
    core = BrokerCore(
        session.session_id, store, session.policy, resolver, approvals=DenyAll(), executor=executor
    )
    token, _ = store.issue(
        CapabilitySpec(
            provider="github",
            hosts=["api.github.com"],
            methods=["GET", "POST"],
            secret=SecretRef(service="github-token"),
        )
    )
    response = core.handle(make_request(token, method="POST", body=b"{}"))
    assert response.reason == "approval_denied"
    assert executor.calls == []


def test_file_approval_gate_allows_when_answered(session, store, executor, resolver):
    gate = FileApprovalGate(session.paths.root / "approvals", timeout=2.0, poll=0.05)

    class ImmediateGate(ApprovalGate):
        """Answers its own request the way an operator at a terminal would."""

        def decide(self, request):
            gate.answer(request.request_id, approved=True)
            return gate.decide(request)

    core = BrokerCore(
        session.session_id,
        store,
        session.policy,
        resolver,
        approvals=ImmediateGate(),
        executor=executor,
    )
    token, _ = store.issue(
        CapabilitySpec(
            provider="github",
            hosts=["api.github.com"],
            methods=["POST"],
            secret=SecretRef(service="github-token"),
        )
    )
    assert core.handle(make_request(token, method="POST", body=b"{}")).decision == "allow"


def test_unanswered_approval_times_out_as_a_denial(session):
    gate = FileApprovalGate(session.paths.root / "approvals", timeout=0.3, poll=0.05)
    from agentsandbox.broker.approvals import ApprovalRequest

    request = ApprovalRequest(
        session_id=session.session_id,
        cap_id="cap-x",
        provider="github",
        method="POST",
        url="https://api.github.com/x",
    )
    assert gate.decide(request) is False


def test_basic_and_header_injection_shapes(session, store, executor, resolver):
    core = BrokerCore(
        session.session_id, store, session.policy, resolver, approvals=AllowAll(), executor=executor
    )
    token, _ = store.issue(
        CapabilitySpec(
            provider="x",
            hosts=["api.github.com"],
            secret=SecretRef(service="github-token"),
            injection=InjectionSpec(kind="basic", username="acme"),
        )
    )
    core.handle(make_request(token))
    name, value = executor.last["credential_headers"][0]
    assert name == "Authorization"
    assert base64.b64decode(value.split()[1]).decode() == f"acme:{SECRET}"

    token2, _ = store.issue(
        CapabilitySpec(
            provider="x",
            hosts=["api.github.com"],
            secret=SecretRef(service="github-token"),
            injection=InjectionSpec(kind="header", header="X-Api-Key", template="{secret}"),
        )
    )
    core.handle(make_request(token2))
    assert executor.last["credential_headers"] == [("X-Api-Key", SECRET)]


def test_upstream_failure_becomes_a_502_without_leaking_detail(session, store, resolver):
    class FailingExecutor:
        def execute(self, *args, **kwargs):
            raise UpstreamError("upstream tls failure: SSLCertVerificationError")

    core = BrokerCore(
        session.session_id,
        store,
        session.policy,
        resolver,
        approvals=AllowAll(),
        executor=FailingExecutor(),
    )
    token, _ = store.issue(
        CapabilitySpec(
            provider="github", hosts=["api.github.com"], secret=SecretRef(service="github-token")
        )
    )
    response = core.handle(make_request(token))
    assert response.status_code == 502
    assert response.reason == "upstream_failed"


def test_audit_log_never_contains_the_secret_or_the_placeholder(
    session, store, executor, resolver, github_capability
):
    audit = AuditLog(session.paths.audit_log, session.session_id)
    core = BrokerCore(
        session.session_id,
        store,
        session.policy,
        resolver,
        audit=audit,
        approvals=AllowAll(),
        executor=executor,
    )
    token, _ = github_capability
    core.handle(make_request(token))

    raw = session.paths.audit_log.read_text()
    assert SECRET not in raw
    assert token not in raw
    assert "cap-" in raw  # the short id is what gets logged instead


def test_request_and_response_round_trip_over_json():
    request = BrokerRequest(
        session_id="s",
        capability="cap_v1_x",
        method="POST",
        scheme="https",
        host="api.github.com",
        port=443,
        target="/x",
        headers=[("A", "b")],
        body=b"\x00\x01binary",
    )
    restored = BrokerRequest.from_dict(json.loads(request.to_json()))
    assert restored == request

    response = BrokerResponse(200, [("A", "b")], b"\x00body", "allow", "", "cap-1")
    assert BrokerResponse.from_dict(json.loads(response.to_json())) == response


def test_scrub_secret_handles_empty_secret():
    assert scrub_secret(b"body", "") == b"body"


class CountingProvider(StaticResolver):  # noqa: F811
    """Every fetch increments a counter; used to prove the cache works."""

    def __init__(self, secret: str):
        super().__init__({"t": secret})
        self.calls = 0

    def fetch(self, ref):
        self.calls += 1
        return super().fetch(ref)


def test_the_keychain_is_not_asked_for_the_same_credential_twice(store):
    """Five brokered requests, one Keychain prompt - not five."""
    from agentsandbox.broker.core import BrokerCore
    from agentsandbox.broker.approvals import AllowAll
    from agentsandbox.netpolicy import DestinationPolicy
    from helpers import RecordingExecutor, make_request

    provider = CountingProvider("ghp_the-real-secret")
    resolver = SecretResolver(providers={"keychain": provider}, cache_ttl=300)
    policy = DestinationPolicy(allow_hosts=["api.github.com"])
    executor = RecordingExecutor()
    core = BrokerCore("s", store, policy, resolver, approvals=AllowAll(), executor=executor)

    token, _ = store.issue(
        CapabilitySpec(
            provider="x", hosts=["api.github.com"],
            secret=SecretRef(service="t"),
        )
    )
    for _ in range(5):
        assert core.handle(make_request(token)).decision == "allow"

    assert provider.calls == 1
    assert executor.calls[0]["credential_headers"] == [("Authorization", "Bearer ghp_the-real-secret")]
