"""The capability model: bindings, budgets, expiry and revocation."""

from __future__ import annotations

import json
import time

import pytest

from agentsandbox.capabilities import (
    AwsAutosignSpec,
    CapabilitySpec,
    CapabilityStore,
    InjectionRule,
    InjectionSpec,
    SecretRef,
    find_placeholders,
    exported_names,
    new_dummy_aws_credentials,
    rebuild_guest_env,
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
            label="test",
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
            CapabilitySpec(label=f"p{i}", hosts=["api.github.com"], secret=SecretRef(service="x"))
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
                label="aws",
                hosts=["api.github.com"],
                secret=SecretRef(service="x"),
                injection_rules=[InjectionRule(injection=InjectionSpec(kind="aws_sigv4"))],
            )
        )
    assert exc.value.reason == "unsupported_injection"


def test_header_injection_requires_a_secret_placeholder():
    with pytest.raises(PolicyDenied):
        InjectionSpec(kind="header", header="X-Api-Key", template="constant").validate()


def test_body_injection_is_supported_with_no_extra_fields():
    InjectionSpec(kind="body").validate()


def _two_rule_capability(store) -> tuple:
    """One capability, two hosts, two mechanisms - basic auth against
    host-a, body substitution against host-b, both reachable through the
    same single placeholder."""
    return store.issue(
        CapabilitySpec(
            label="two-mechanisms",
            hosts=["host-a.example.com", "host-b.example.com"],
            methods=["POST", "PUT"],
            secret=SecretRef(service="x"),
            injection_rules=[
                InjectionRule(
                    hosts=["host-a.example.com"],
                    injection=InjectionSpec(kind="basic", username="svc-a"),
                ),
                InjectionRule(
                    hosts=["host-b.example.com"],
                    injection=InjectionSpec(kind="body"),
                ),
            ],
        )
    )


HOST_A = Destination("https", "host-a.example.com", 443)
HOST_B = Destination("https", "host-b.example.com", 443)


def test_pick_injection_dispatches_by_which_rule_matches(store):
    _, cap = _two_rule_capability(store)
    assert cap.pick_injection(HOST_A, "POST", "/x").kind == "basic"
    assert cap.pick_injection(HOST_B, "PUT", "/x").kind == "body"


def test_validate_returns_the_injection_that_actually_applies(store):
    _, cap = _two_rule_capability(store)
    active = cap.validate(session_id=cap.session_id, dest=HOST_A, method="POST", path="/x")
    assert active.kind == "basic"
    active = cap.validate(session_id=cap.session_id, dest=HOST_B, method="PUT", path="/x")
    assert active.kind == "body"


def test_a_request_inside_scope_but_outside_every_rule_is_denied(store):
    """Authorization passing (the request is inside the capability's own
    hosts/methods) does not mean some rule has to match - a hole between
    the outer scope and the rules is a bug, and must fail closed, not fall
    back to any one mechanism silently."""
    _, cap = store.issue(
        CapabilitySpec(
            label="narrow-rules",
            hosts=["host-a.example.com", "host-b.example.com"],
            methods=["POST"],
            secret=SecretRef(service="x"),
            injection_rules=[
                InjectionRule(hosts=["host-a.example.com"], injection=InjectionSpec(kind="body")),
            ],
        )
    )
    with pytest.raises(PolicyDenied) as exc:
        cap.pick_injection(HOST_B, "POST", "/x")
    assert exc.value.reason == "no_matching_injection_rule"


def test_no_injection_specified_means_one_unrestricted_bearer_rule(store, github_capability):
    """Every capability that never opts into multiple rules gets exactly
    the one implicit rule that has always been the default: bearer,
    matching anything already inside the capability's own scope."""
    _, cap = github_capability
    assert len(cap.injection_rules) == 1
    assert cap.injection_rules[0].hosts == []
    assert cap.pick_injection(GITHUB, "GET", "/x").kind == "bearer"


def test_injection_rules_round_trip_through_to_dict(store):
    _, cap = _two_rule_capability(store)
    from agentsandbox.capabilities import Capability

    restored = Capability.from_dict(cap.to_dict())
    assert len(restored.injection_rules) == 2
    assert restored.pick_injection(HOST_A, "POST", "/x").kind == "basic"
    assert restored.pick_injection(HOST_B, "PUT", "/x").kind == "body"


def test_dummy_aws_credentials_look_like_a_real_access_key():
    access_key_id, secret_access_key = new_dummy_aws_credentials()
    assert access_key_id.startswith("AKIA")
    assert len(access_key_id) == 20
    assert access_key_id.isalnum() and access_key_id.isupper()
    assert secret_access_key

    # Minted per session, not a fixed constant - two calls must not agree.
    other_access_key_id, other_secret_access_key = new_dummy_aws_credentials()
    assert other_access_key_id != access_key_id
    assert other_secret_access_key != secret_access_key


def test_aws_autosign_spec_round_trips_through_to_dict():
    spec = AwsAutosignSpec(
        signing_secret=SecretRef(backend="file", service="/tmp/cred.json"),
        access_key_id="AKIAABCDEFGHIJKLMNOP",
    )
    restored = AwsAutosignSpec.from_dict(spec.to_dict())
    assert restored == spec


def test_public_view_never_contains_the_token(store, github_capability):
    token, cap = github_capability
    assert token not in json.dumps(cap.public_view())


def test_store_is_reloaded_when_another_process_writes_it(session, store):
    other = CapabilityStore(session.paths.capabilities, session.session_id)
    token, cap = other.issue(
        CapabilitySpec(label="test", hosts=["api.github.com"], secret=SecretRef(service="x"))
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
            label="test", hosts=["api.github.com"], secret=SecretRef(service="x"), ttl_seconds=1
        )
    )
    assert store.prune_expired(now=time.time() + 5) == 1
    assert store.list() == []


def test_a_deny_list_carves_exceptions_out_of_a_broad_allow(store):
    """Allow the API, keep the destructive corner of it out of reach."""
    token, cap = store.issue(
        CapabilitySpec(
            label="svc",
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
            label="svc",
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
            label="svc",
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
        CapabilitySpec(label="test", hosts=["api.github.com"], secret=SecretRef(service="x"))
    )
    assert cap.expires_at == 0.0
    cap.check_alive(now=time.time() + 86400 * 30)


def test_renew_extends_an_expired_capability(store):
    _, cap = store.issue(
        CapabilitySpec(
            label="test",
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
            label="test",
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
        CapabilitySpec(label="test", hosts=["api.github.com"], secret=SecretRef(service="x"))
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
            label="test",
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
            label="test",
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
            label="test",
            hosts=["api.github.com"],
            secret=SecretRef(service="x"),
            ttl_seconds=1,
        )
    )
    renewed = store.renew(cap.cap_id, ttl_seconds=600)
    assert renewed.expires_at > time.time() + 550


# -- rebuilding a guest's capabilities.env -----------------------------------


def _issued(store, label):
    return store.issue(CapabilitySpec(label=label, hosts=[f"{label}.com"], secret=SecretRef(service=label)))


def test_rebuild_guest_env_renames_adds_and_keeps_everything_else(tmp_path):
    store = CapabilityStore(tmp_path / "caps.json", "s")
    token_a, _ = _issued(store, "a")
    token_gone, cap_gone = _issued(store, "gone")
    store.revoke(cap_gone.cap_id)
    token_b, _ = _issued(store, "b")
    before = (
        "export AWS_ACCESS_KEY_ID=AKIADUMMY\n"
        f"export A={token_a}\n"
        f"export GONE={token_gone}\n"
        "export FORGED=cap_v1_not_a_real_one\n"
    )

    after, missing = rebuild_guest_env(
        before, store.list(), {"a": "A_RENAMED", "b": "B"}, {"b": token_b}
    )

    assert missing == []
    assert after.splitlines() == [
        "export AWS_ACCESS_KEY_ID=AKIADUMMY",  # not a capability: kept as is
        "export FORGED=cap_v1_not_a_real_one",  # hashes to nothing: not ours to drop
        f"export A_RENAMED={token_a}",  # same placeholder, new name
        f"export B={token_b}",  # minted just now
    ]  # GONE was revoked: dropped
    assert exported_names(after) == {"AWS_ACCESS_KEY_ID", "FORGED", "A_RENAMED", "B"}


def test_rebuild_guest_env_is_stable_and_reports_what_it_cannot_recover(tmp_path):
    store = CapabilityStore(tmp_path / "caps.json", "s")
    token_a, _ = _issued(store, "a")
    _issued(store, "lost")
    current = f"export A={token_a}\n"

    after, missing = rebuild_guest_env(current, store.list(), {"a": "A", "lost": "LOST"}, {})

    assert after == current  # nothing changed, so nothing to write
    assert missing == ["lost"]


def test_rebuild_guest_env_drops_a_label_that_lost_its_guest_env(tmp_path):
    store = CapabilityStore(tmp_path / "caps.json", "s")
    token_a, _ = _issued(store, "a")

    after, _ = rebuild_guest_env(f"export BOX=1\nexport A={token_a}\n", store.list(), {}, {})

    assert after == "export BOX=1\n"
