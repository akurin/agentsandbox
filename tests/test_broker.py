"""The broker: the only place a real credential is ever used.

These tests are the "real credentials never appear inside the VM" and
"a placeholder works only for its approved destination and operation"
acceptance criteria, checked at the component that enforces them.
"""

from __future__ import annotations

import base64
import json
import time

import pytest


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


def test_usage_accumulates_without_ever_blocking(session, store, executor, resolver):
    """There is no request budget: a long-running agent is not rate-limited
    by us. Usage is still recorded, because the audit trail wants it."""
    core = BrokerCore(
        session.session_id, store, session.policy, resolver, approvals=AllowAll(), executor=executor
    )
    token, cap = store.issue(
        CapabilitySpec(
            provider="github",
            hosts=["api.github.com"],
            secret=SecretRef(service="github-token"),
        )
    )
    for _ in range(50):
        assert core.handle(make_request(token)).decision == "allow"
    assert len(executor.calls) == 50
    assert store.lookup(token).used_requests == 50


def test_an_expired_capability_says_which_one_and_how_to_extend_it(
    session, store, executor, resolver
):
    """An expired grant is otherwise indistinguishable from a broken
    credential - the agent cannot report anything useful, and whoever reads
    the audit log has to reconstruct the context by hand."""
    core = BrokerCore(
        session.session_id, store, session.policy, resolver, approvals=AllowAll(), executor=executor
    )
    token, cap = store.issue(
        CapabilitySpec(
            provider="github",
            hosts=["api.github.com"],
            secret=SecretRef(service="github-token"),
            ttl_seconds=-1,
        )
    )
    response = core.handle(make_request(token))
    assert response.reason == "capability_expired"

    body = json.loads(response.body)
    assert body["capability"] == cap.cap_id
    assert "cap renew" in body["remedy"]
    assert cap.cap_id in body["remedy"]
    assert executor.calls == []


def test_a_scope_denial_offers_no_remedy(session, store, executor, resolver):
    """Telling the guest how to widen its own scope is advice on getting
    around the policy. Only running out of time earns a remedy."""
    core = BrokerCore(
        session.session_id, store, session.policy, resolver, approvals=AllowAll(), executor=executor
    )
    token, _ = store.issue(
        CapabilitySpec(
            provider="github",
            hosts=["api.github.com"],
            secret=SecretRef(service="github-token"),
            path_globs=["/user"],
        )
    )
    response = core.handle(make_request(token, target="/admin/keys"))
    assert response.reason == "path_not_permitted"
    assert "remedy" not in json.loads(response.body)


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


def test_a_capability_issued_after_the_broker_started_is_usable(session, executor, resolver):
    """No restart to add a credential: the store is re-read when it changes.

    The CLI issues into the same file the running broker holds, so `asbx cap
    issue` against a live session takes effect on the next request.
    """
    from agentsandbox.broker.approvals import AllowAll
    from agentsandbox.capabilities import CapabilityStore

    # The broker starts with an empty store, as it would at session start.
    store = CapabilityStore(session.paths.capabilities, session.session_id)
    core = BrokerCore(
        session.session_id, store, session.policy, resolver, approvals=AllowAll(), executor=executor
    )
    assert store.list() == []

    # A second process (the CLI) issues into the same file.
    issuing = CapabilityStore(session.paths.capabilities, session.session_id)
    token, cap = issuing.issue(
        CapabilitySpec(
            provider="github", hosts=["api.github.com"], secret=SecretRef(service="github-token")
        )
    )

    # The running broker picks it up without being restarted.
    assert core.handle(make_request(token)).decision == "allow"


def test_a_revocation_from_another_process_takes_effect_immediately(broker, store, github_capability):
    """The same path in reverse - revoking must not need a restart either."""
    from agentsandbox.capabilities import CapabilityStore

    token, cap = github_capability
    assert broker.handle(make_request(token)).decision == "allow"

    other = CapabilityStore(store.path, store.session_id)
    assert other.revoke(cap.cap_id) is True

    assert broker.handle(make_request(token)).reason == "capability_revoked"


# -- pass (passwordstore.org) ------------------------------------------------


def test_pass_returns_the_first_line_only(tmp_path):
    """A pass entry is `secret\\nmetadata...` by convention."""
    from agentsandbox.keychain import PassProvider

    fake = tmp_path / "pass"
    fake.write_text("#!/bin/sh\nprintf 'the-secret\\nurl: https://example.com\\nuser: bob\\n'\n")
    fake.chmod(0o755)

    got = PassProvider(binary=str(fake)).fetch(SecretRef(backend="pass", service="work/wiremock"))
    assert got == "the-secret"


def test_pass_builds_the_entry_path_from_service_and_account(tmp_path):
    from agentsandbox.keychain import PassProvider

    fake = tmp_path / "pass"
    fake.write_text('#!/bin/sh\necho "asked-for:$2"\n')
    fake.chmod(0o755)

    got = PassProvider(binary=str(fake)).fetch(
        SecretRef(backend="pass", service="work/wiremock", account="developer")
    )
    assert got == "asked-for:work/wiremock/developer"


def test_a_missing_pass_entry_explains_itself(tmp_path):
    from agentsandbox.errors import BrokerError
    from agentsandbox.keychain import PassProvider

    fake = tmp_path / "pass"
    fake.write_text('#!/bin/sh\necho "Error: nope is not in the password store." >&2\nexit 1\n')
    fake.chmod(0o755)

    with pytest.raises(BrokerError) as exc:
        PassProvider(binary=str(fake)).fetch(SecretRef(backend="pass", service="nope"))
    assert "nope" in str(exc.value)
    assert "password store" in str(exc.value)


def test_a_pass_secret_is_registered_for_redaction(tmp_path):
    """Anything the broker reads must never survive into a log line."""
    from agentsandbox.audit import redactor
    from agentsandbox.keychain import PassProvider

    fake = tmp_path / "pass"
    fake.write_text("#!/bin/sh\necho 'hunter2-hunter2-hunter2'\n")
    fake.chmod(0o755)

    PassProvider(binary=str(fake)).fetch(SecretRef(backend="pass", service="x"))
    assert "hunter2-hunter2-hunter2" not in redactor.text("token=hunter2-hunter2-hunter2")


def test_the_resolver_knows_the_pass_backend():
    from agentsandbox.keychain import PassProvider, SecretResolver

    assert isinstance(SecretResolver().providers["pass"], PassProvider)


def test_pass_consults_the_store_it_was_told_to(tmp_path):
    """A per-project database is selected explicitly, never inherited."""
    from agentsandbox.keychain import PassProvider

    fake = tmp_path / "pass"
    fake.write_text('#!/bin/sh\necho "store=$PASSWORD_STORE_DIR"\n')
    fake.chmod(0o755)

    got = PassProvider(binary=str(fake)).fetch(
        SecretRef(backend="pass", service="x", store=str(tmp_path / "neo-store"))
    )
    assert got == f"store={tmp_path / 'neo-store'}"


def test_two_stores_with_the_same_entry_name_do_not_share_a_cache(tmp_path):
    """`wiremock/developer` in two databases is two different secrets."""
    from agentsandbox.keychain import PassProvider, SecretResolver

    fake = tmp_path / "pass"
    fake.write_text('#!/bin/sh\necho "secret-from:$PASSWORD_STORE_DIR"\n')
    fake.chmod(0o755)

    resolver = SecretResolver(providers={"pass": PassProvider(binary=str(fake))}, cache_ttl=300)
    work = resolver.fetch(SecretRef(backend="pass", service="wiremock", store="/tmp/work"))
    personal = resolver.fetch(SecretRef(backend="pass", service="wiremock", store="/tmp/personal"))

    assert work == "secret-from:/tmp/work"
    assert personal == "secret-from:/tmp/personal"


# -- one unlock, then days -----------------------------------------------------


def test_a_held_secret_never_expires(tmp_path):
    """An unattended agent runs for days with nobody to answer a prompt.

    The unlock happens once in the foreground; after `hold_for_session` the
    broker must never go back to the store, because there is no terminal left
    to prompt in.
    """
    from agentsandbox.keychain import SecretResolver

    provider = CountingProvider("the-secret")
    resolver = SecretResolver(providers={"keychain": provider}, cache_ttl=1)
    ref = SecretRef(service="t")

    assert resolver.fetch(ref) == "the-secret"
    resolver.hold_for_session()

    time.sleep(1.1)  # well past the original TTL
    assert resolver.fetch(ref) == "the-secret"
    assert provider.calls == 1


def test_holding_extends_secrets_read_before_the_call(tmp_path):
    """The foreground read happens first; holding must not discard it."""
    from agentsandbox.keychain import SecretResolver

    provider = CountingProvider("the-secret")
    resolver = SecretResolver(providers={"keychain": provider}, cache_ttl=0.01)
    resolver.fetch(SecretRef(service="t"))
    resolver.hold_for_session()

    time.sleep(0.05)
    resolver.fetch(SecretRef(service="t"))
    assert provider.calls == 1


def test_refresh_drops_the_held_secrets(tmp_path):
    """A credential rotated upstream has to be re-readable without a restart."""
    from agentsandbox.keychain import SecretResolver

    provider = CountingProvider("old-secret")
    resolver = SecretResolver(providers={"keychain": provider}, cache_ttl=1)
    resolver.fetch(SecretRef(service="t"))
    resolver.hold_for_session()

    resolver.clear_cache()
    resolver.fetch(SecretRef(service="t"))
    assert provider.calls == 2


def test_the_broker_control_channel_refuses_unknown_commands(session, broker):
    """The operator channel is narrow: one verb, and it says so."""
    from agentsandbox.broker.server import BrokerServer, issue_token

    token = issue_token(session.paths.broker_token)
    server = BrokerServer(broker, session.paths.broker_socket, token)
    try:
        import json as _json

        assert _json.loads(server.handle_command("refresh-secrets"))["ok"] is True
        answer = _json.loads(server.handle_command("rm -rf /"))
        assert answer["ok"] is False
        assert "unknown command" in answer["error"]
    finally:
        server.server_close()


# -- basic auth: whose account? ----------------------------------------------


def _basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def _basic_capability(store, username="developer"):
    return store.issue(
        CapabilitySpec(
            provider="wiremock",
            hosts=["api.github.com"],
            secret=SecretRef(service="github-token"),
            injection=InjectionSpec(kind="basic", username=username),
        )
    )


def test_the_capability_decides_which_account_is_used(broker, executor, store):
    """The guest cannot select an account by changing the username."""
    token, _ = _basic_capability(store)
    broker.handle(make_request(token, headers=[("Authorization", _basic("developer", token))]))

    name, value = executor.last["credential_headers"][0]
    assert name == "Authorization"
    assert base64.b64decode(value.split()[1]).decode() == f"developer:{SECRET}"


def test_a_different_username_is_refused_rather_than_silently_replaced(broker, executor, store):
    """Substituting silently makes a typo look like it worked."""
    token, _ = _basic_capability(store)
    response = broker.handle(
        make_request(token, headers=[("Authorization", _basic("wrong_user", token))])
    )

    assert response.decision == "deny"
    assert response.reason == "username_mismatch"
    assert b"developer" in response.body  # says which account it does authenticate as
    assert executor.calls == []  # and never reached the upstream


def test_an_empty_username_is_allowed(broker, executor, store):
    """Token-style APIs routinely send `:token` with no user part."""
    token, _ = _basic_capability(store)
    assert broker.handle(
        make_request(token, headers=[("Authorization", _basic("", token))])
    ).decision == "allow"


def test_bearer_capabilities_are_unaffected_by_the_username_check(broker, executor, github_capability):
    token, _ = github_capability
    assert broker.handle(make_request(token)).decision == "allow"


def test_a_password_with_anything_appended_is_refused(broker, executor, store):
    """`-u user:$CAP:123` must not quietly work.

    Detection has to be lenient to find a placeholder inside base64; that is
    not a licence to accept a credential the agent built wrong.
    """
    token, _ = _basic_capability(store)
    response = broker.handle(
        make_request(token, headers=[("Authorization", _basic("developer", f"{token}:123"))])
    )

    assert response.decision == "deny"
    assert response.reason == "malformed_credential"
    assert executor.calls == []


def test_a_malformed_credential_never_reaches_the_upstream(broker, executor, store):
    """The refusal is also what stops a placeholder leaving the sandbox."""
    token, _ = _basic_capability(store)
    broker.handle(
        make_request(token, headers=[("Authorization", _basic("developer", f"prefix{token}"))])
    )
    assert executor.calls == []


def test_an_exact_placeholder_password_is_accepted(broker, executor, store):
    token, _ = _basic_capability(store)
    assert broker.handle(
        make_request(token, headers=[("Authorization", _basic("developer", token))])
    ).decision == "allow"


def test_the_suggested_remedy_is_a_command_that_actually_parses(session, store, resolver):
    """A remedy that does not run is worse than no remedy: it sends whoever
    reads it off debugging their shell instead of their sandbox."""
    import shlex

    from agentsandbox.cli import build_parser

    core = BrokerCore(session.session_id, store, session.policy, resolver)
    token, cap = store.issue(
        CapabilitySpec(
            provider="github",
            hosts=["api.github.com"],
            secret=SecretRef(service="github-token"),
            ttl_seconds=-1,
        )
    )
    remedy = json.loads(core.handle(make_request(token)).body)["remedy"]
    command = remedy.split(": ", 1)[1].replace("<seconds>", "600")

    args = build_parser().parse_args(shlex.split(command)[1:])
    assert args.cap_id == cap.cap_id
    assert args.session == session.session_id
    assert args.ttl == 600
