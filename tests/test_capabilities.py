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
from agentsandbox.errors import CapabilityError, PolicyDenied
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


def test_renew_extends_an_expired_capability(store):
    _, cap = store.issue(
        CapabilitySpec(
            provider="test",
            hosts=["api.github.com"],
            secret=SecretRef(service="x"),
            ttl_seconds=1,
        )
    )
    with pytest.raises(PolicyDenied):
        cap.check_alive(now=time.time() + 2)

    renewed = store.renew(cap.cap_id, ttl_seconds=3600)
    assert renewed is not None
    renewed.check_alive(now=time.time() + 2)


def test_renewing_an_unknown_capability_reports_it(store):
    assert store.renew("nosuchid", ttl_seconds=60) is None


def test_renew_to_zero_ttl_means_never_expires(store):
    _, cap = store.issue(
        CapabilitySpec(
            provider="test",
            hosts=["api.github.com"],
            secret=SecretRef(service="x"),
            ttl_seconds=1,
        )
    )
    renewed = store.renew(cap.cap_id, ttl_seconds=0)
    assert renewed.expires_at == 0.0
    renewed.check_alive(now=time.time() + 86400)


def test_usage_is_counted_even_though_nothing_caps_it(store):
    """Budgets are gone; the counters are not.

    They are what `asbx cap ls` and the audit log report, and "how much has
    this capability actually been used" stays worth knowing when the answer
    no longer changes any decision.
    """
    token, cap = store.issue(
        CapabilitySpec(provider="test", hosts=["api.github.com"], secret=SecretRef(service="x"))
    )
    for _ in range(300):
        store.record_usage(cap, 4096)
    reloaded = store.lookup(token)
    assert reloaded.used_requests == 300
    assert reloaded.used_bytes == 300 * 4096
    reloaded.check_alive()
    assert reloaded.public_view()["requests"] == 300


def test_renew_does_not_reset_the_usage_counters(store):
    """A capability renewed four times should look like it in the audit log."""
    token, cap = store.issue(
        CapabilitySpec(
            provider="test",
            hosts=["api.github.com"],
            secret=SecretRef(service="x"),
            ttl_seconds=1,
        )
    )
    store.record_usage(cap, 100)
    store.renew(cap.cap_id, ttl_seconds=3600)
    assert store.lookup(token).used_requests == 1


def test_a_revoked_capability_is_not_renewable(store, github_capability):
    """Revocation is a decision, not a timeout."""
    _, cap = github_capability
    store.revoke(cap.cap_id)
    with pytest.raises(CapabilityError):
        store.renew(cap.cap_id, ttl_seconds=3600)


def test_a_renewal_is_visible_to_an_already_loaded_store(store):
    """The broker holds its own CapabilityStore on the same file.

    Renewal is useless if the running broker does not notice it - not needing
    a restart is the entire point.
    """
    token, cap = store.issue(
        CapabilitySpec(
            provider="test",
            hosts=["api.github.com"],
            secret=SecretRef(service="x"),
            ttl_seconds=1,
        )
    )
    broker_side = CapabilityStore(store.path, store.session_id)
    broker_side.lookup(token)  # warm whatever cache it keeps
    later = time.time() + 5
    with pytest.raises(PolicyDenied):
        broker_side.lookup(token).check_alive(now=later)

    store.renew(cap.cap_id, ttl_seconds=3600)
    broker_side.lookup(token).check_alive(now=later)


def test_renewal_is_measured_from_now_not_from_the_old_expiry(store):
    """A grant that lapsed overnight should come back with a full window."""
    _, cap = store.issue(
        CapabilitySpec(
            provider="test",
            hosts=["api.github.com"],
            secret=SecretRef(service="x"),
            ttl_seconds=1,
        )
    )
    renewed = store.renew(cap.cap_id, ttl_seconds=600)
    assert renewed.expires_at > time.time() + 550
