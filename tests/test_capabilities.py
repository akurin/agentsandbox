"""The capability model: bindings, budgets, expiry and revocation."""

from __future__ import annotations

import json
import time

import pytest

from agentsandbox.capabilities import (
    CapabilitySpec,
    CapabilityStore,
    InjectionSpec,
    SecretRef,
    find_placeholders,
    res_matches,
)
from agentsandbox.errors import PolicyDenied
from agentsandbox.netpolicy import Destination

GITHUB = Destination("https", "api.github.com", 443)


def test_placeholder_is_returned_once_and_stored_only_as_a_hash(store, github_capability):
    token, cap = github_capability
    assert token.startswith("cap_v1_")

    raw = json.loads(store.path.read_text())
    serialised = json.dumps(raw)
    # The token itself must not be recoverable from the store on disk.
    assert token not in serialised
    assert cap.token_hash in serialised
    assert store.lookup(token) is not None


def test_store_file_is_owner_only(store, github_capability):
    assert store.path.stat().st_mode & 0o077 == 0


def test_capability_covers_only_its_own_destination(store, github_capability):
    _, cap = github_capability
    cap.check_destination(GITHUB)
    with pytest.raises(PolicyDenied) as exc:
        cap.check_destination(Destination("https", "api.example.com", 443))
    assert exc.value.reason == "host_not_permitted"


def test_credentials_are_never_attached_over_plaintext(store, github_capability):
    _, cap = github_capability
    with pytest.raises(PolicyDenied) as exc:
        cap.check_destination(Destination("http", "api.github.com", 80))
    assert exc.value.reason == "insecure_scheme"


def test_method_and_path_are_both_enforced(store, github_capability):
    _, cap = github_capability
    cap.check_operation("GET", "/repos/acme/api/issues")
    with pytest.raises(PolicyDenied) as exc:
        cap.check_operation("DELETE", "/repos/acme/api/issues")
    assert exc.value.reason == "method_not_permitted"
    with pytest.raises(PolicyDenied) as exc:
        cap.check_operation("GET", "/user/keys")
    assert exc.value.reason == "path_not_permitted"


def test_resource_binding_is_by_path_segment(store, github_capability):
    _, cap = github_capability
    cap.check_operation("GET", "/repos/acme/api/pulls")
    # A repository whose name merely starts the same must not match.
    with pytest.raises(PolicyDenied) as exc:
        cap.check_operation("GET", "/repos/acme/api-secrets/pulls")
    assert exc.value.reason == "resource_not_permitted"


def test_res_matches_edge_cases():
    assert res_matches("repo:acme/api", "/repos/acme/api")
    assert res_matches("repo:acme/api", "/repos/acme/api/issues/1")
    assert not res_matches("repo:acme/api", "/repos/acme/apifoo")
    assert not res_matches("bucket:", "/anything")


def test_a_capability_from_another_session_is_worthless(store, github_capability):
    _, cap = github_capability
    with pytest.raises(PolicyDenied) as exc:
        cap.check_session("some-other-session")
    assert exc.value.reason == "wrong_session"


def test_expiry(store):
    token, cap = store.issue(
        CapabilitySpec(
            provider="test",
            hosts=["api.github.com"],
            secret=SecretRef(service="x"),
            ttl_seconds=1,
        )
    )
    cap.check_alive()
    with pytest.raises(PolicyDenied) as exc:
        cap.check_alive(now=time.time() + 2)
    assert exc.value.reason == "capability_expired"


def test_request_budget_is_spent(store):
    token, cap = store.issue(
        CapabilitySpec(
            provider="test",
            hosts=["api.github.com"],
            secret=SecretRef(service="x"),
            max_requests=2,
        )
    )
    store.record_usage(cap, 10)
    store.record_usage(cap, 10)
    reloaded = store.lookup(token)
    assert reloaded.used_requests == 2
    with pytest.raises(PolicyDenied) as exc:
        reloaded.check_alive()
    assert exc.value.reason == "request_budget_exhausted"


def test_byte_budget_is_spent(store):
    token, cap = store.issue(
        CapabilitySpec(
            provider="test",
            hosts=["api.github.com"],
            secret=SecretRef(service="x"),
            max_requests=100,
            max_total_bytes=1000,
        )
    )
    store.record_usage(cap, 1500)
    with pytest.raises(PolicyDenied) as exc:
        store.lookup(token).check_alive()
    assert exc.value.reason == "byte_budget_exhausted"


def test_revocation_is_immediate(store, github_capability):
    token, cap = github_capability
    assert store.revoke(cap.cap_id) is True
    with pytest.raises(PolicyDenied) as exc:
        store.lookup(token).check_alive()
    assert exc.value.reason == "capability_revoked"


def test_revoke_all_kills_every_capability(store):
    for i in range(3):
        store.issue(
            CapabilitySpec(provider=f"p{i}", hosts=["api.github.com"], secret=SecretRef(service="x"))
        )
    assert store.revoke_all() == 3
    assert all(cap.revoked for cap in store.list())


def test_destroy_wipes_the_store(store, github_capability):
    token, _ = github_capability
    store.destroy()
    assert not store.path.exists()
    assert store.lookup(token) is None


def test_unsupported_injection_is_refused_at_issue_time(store):
    with pytest.raises(PolicyDenied) as exc:
        store.issue(
            CapabilitySpec(
                provider="aws",
                hosts=["api.github.com"],
                secret=SecretRef(service="x"),
                injection=InjectionSpec(kind="aws_sigv4"),
            )
        )
    assert exc.value.reason == "unsupported_injection"


def test_header_injection_requires_a_secret_placeholder():
    with pytest.raises(PolicyDenied):
        InjectionSpec(kind="header", header="X-Api-Key", template="constant").validate()


def test_public_view_never_contains_the_token(store, github_capability):
    token, cap = github_capability
    assert token not in json.dumps(cap.public_view())


def test_mutating_methods_need_approval_by_default(store):
    _, cap = store.issue(
        CapabilitySpec(
            provider="test",
            hosts=["api.github.com"],
            methods=["GET", "POST"],
            secret=SecretRef(service="x"),
        )
    )
    assert cap.needs_approval("POST")
    assert not cap.needs_approval("GET")


def test_store_is_reloaded_when_another_process_writes_it(session, store):
    other = CapabilityStore(session.paths.capabilities, session.session_id)
    token, cap = other.issue(
        CapabilitySpec(provider="test", hosts=["api.github.com"], secret=SecretRef(service="x"))
    )
    # The first store instance had already loaded an empty file.
    assert store.lookup(token) is not None


def test_find_placeholders_extracts_tokens():
    text = "Authorization: Bearer cap_v1_abcdefghijklmnopqrstuvwx and cap_v1_0123456789abcdefghijklmn"
    found = find_placeholders(text)
    assert len(found) == 2
    assert all(f.startswith("cap_v1_") for f in found)


def test_prune_expired(store):
    store.issue(
        CapabilitySpec(
            provider="test", hosts=["api.github.com"], secret=SecretRef(service="x"), ttl_seconds=1
        )
    )
    assert store.prune_expired(now=time.time() + 5) == 1
    assert store.list() == []


def test_a_deny_list_carves_exceptions_out_of_a_broad_allow(store):
    """Allow the API, keep the destructive corner of it out of reach."""
    token, cap = store.issue(
        CapabilitySpec(
            provider="svc",
            hosts=["api.example.com"],
            methods=["GET", "POST", "DELETE"],
            path_globs=["/admin/*"],
            deny_path_globs=["/admin/*/reset", "/admin/shutdown"],
            secret=SecretRef(service="x"),
        )
    )
    cap.check_operation("POST", "/admin/requests/find")
    cap.check_operation("DELETE", "/admin/mappings/abc")

    for denied in ("/admin/requests/reset", "/admin/shutdown"):
        with pytest.raises(PolicyDenied) as exc:
            cap.check_operation("POST", denied)
        assert exc.value.reason == "path_denied"


def test_deny_beats_allow_even_for_an_exact_match(store):
    """Order matters: the deny list is checked first, so it always wins."""
    _, cap = store.issue(
        CapabilitySpec(
            provider="svc",
            hosts=["api.example.com"],
            path_globs=["/thing"],
            deny_path_globs=["/thing"],
            secret=SecretRef(service="x"),
        )
    )
    with pytest.raises(PolicyDenied) as exc:
        cap.check_operation("GET", "/thing")
    assert exc.value.reason == "path_denied"


def test_denied_paths_are_visible_when_reviewing_a_capability(store):
    _, cap = store.issue(
        CapabilitySpec(
            provider="svc",
            hosts=["api.example.com"],
            path_globs=["/*"],
            deny_path_globs=["/dangerous"],
            secret=SecretRef(service="x"),
        )
    )
    assert cap.public_view()["denied_paths"] == ["/dangerous"]


def test_a_capability_does_not_expire_by_default(store):
    """An agent may run unattended for days.

    A capability that dies mid-run fails far from its cause: the agent sees an
    HTTP error from a call that worked an hour earlier. Scope is what contains
    a capability, and scope does not decay.
    """
    _, cap = store.issue(
        CapabilitySpec(provider="test", hosts=["api.github.com"], secret=SecretRef(service="x"))
    )
    assert cap.expires_at == 0.0
    cap.check_alive(now=time.time() + 86400 * 30)


def test_the_request_budget_is_unlimited_by_default(store):
    token, cap = store.issue(
        CapabilitySpec(provider="test", hosts=["api.github.com"], secret=SecretRef(service="x"))
    )
    for _ in range(500):
        store.record_usage(cap, 4096)
    reloaded = store.lookup(token)
    assert reloaded.used_requests == 500
    reloaded.check_alive()


def test_an_unlimited_request_budget_implies_an_unlimited_byte_budget(store):
    """The byte budget derives from the request budget when not set outright.

    Without this, removing one ceiling would leave the other at zero - which
    denies every request rather than allowing them all.
    """
    _, cap = store.issue(
        CapabilitySpec(provider="test", hosts=["api.github.com"], secret=SecretRef(service="x"))
    )
    assert cap.byte_budget == 0
    cap.used_bytes = 10 * 1024**3
    cap.check_alive()


def test_explicit_ceilings_still_apply(store):
    """Unlimited is the default, not the only option."""
    _, cap = store.issue(
        CapabilitySpec(
            provider="test",
            hosts=["api.github.com"],
            secret=SecretRef(service="x"),
            ttl_seconds=60,
            max_requests=1,
        )
    )
    assert cap.expires_at > 0
    cap.used_requests = 1
    with pytest.raises(PolicyDenied) as exc:
        cap.check_alive()
    assert exc.value.reason == "request_budget_exhausted"


def test_usage_is_still_reported_when_unlimited(store):
    """No ceiling is not a reason to stop counting - `asbx cap ls` still shows
    how much a capability has been used."""
    _, cap = store.issue(
        CapabilitySpec(provider="test", hosts=["api.github.com"], secret=SecretRef(service="x"))
    )
    store.record_usage(cap, 2048)
    summary = cap.public_view()
    assert summary["requests"] == "1/unlimited"
    assert summary["bytes"] == "2048/unlimited"
    assert summary["expires_in"] is None
