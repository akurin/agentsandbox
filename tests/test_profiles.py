"""Capability profiles: declare once, issue many."""
import json
import re
from pathlib import Path

import pytest
from agentsandbox.errors import CapabilityError
from agentsandbox import profiles
from agentsandbox.profiles import load_profile, resolve_profile, list_profiles

@pytest.fixture
def profile_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("ASBX_PROFILE_DIR", str(tmp_path))
    return tmp_path

def test_json_profile_parses(profile_dir):
    (profile_dir / "oss.json").write_text(json.dumps({
        "version": 1,
        "capabilities": [
            {"provider": "github", "hosts": ["api.github.com"], "methods": ["GET"], "secret": "keychain:asbx-github:me"}
        ],
    }))
    specs = load_profile(resolve_profile("oss"))
    assert len(specs) == 1
    assert specs[0].provider == "github"
    assert specs[0].hosts == ["api.github.com"]
    assert specs[0].secret.backend == "keychain"

def test_secret_ref_variants(profile_dir):
    (profile_dir / "s.json").write_text(json.dumps({
        "version": 1,
        "capabilities": [
            {"provider": "a", "hosts": ["x.com"], "secret": "keychain:svc:acct"},
            {"provider": "b", "hosts": ["y.com"], "secret": {"backend": "env", "service": "TOKEN"}},
        ],
    }))
    specs = load_profile(resolve_profile("s"))
    assert specs[0].secret.backend == "keychain"
    assert specs[0].secret.service == "svc"
    assert specs[0].secret.account == "acct"
    assert specs[1].secret.backend == "env"
    assert specs[1].secret.service == "TOKEN"

def test_missing_provider_is_an_error(profile_dir):
    (profile_dir / "bad.json").write_text(json.dumps({"version": 1, "capabilities": [{"hosts": ["x.com"], "secret": "keychain:x"}]}))
    with pytest.raises(CapabilityError, match="provider"):
        load_profile(resolve_profile("bad"))

def test_missing_secret_is_an_error(profile_dir):
    (profile_dir / "bad.json").write_text(json.dumps({"version": 1, "capabilities": [{"provider": "x", "hosts": ["x.com"]}]}))
    with pytest.raises(CapabilityError, match="secret"):
        load_profile(resolve_profile("bad"))

def test_no_such_profile_is_an_error():
    with pytest.raises(CapabilityError, match="no profile named"):
        resolve_profile("does-not-exist")

def test_list_profiles_includes_builtin_example():
    names = set(list_profiles())
    assert "example" in names

def test_cli_profile_list(capsys):
    from agentsandbox import cli
    assert cli.main(["profile", "list"]) == 0
    out = capsys.readouterr().out
    assert "example" in out


def test_profiles_can_carry_non_secret_environment(profile_dir):
    """A base URL is configuration, not a credential."""
    from agentsandbox.profiles import load_profile_env

    (profile_dir / "svc.json").write_text(json.dumps({
        "version": 1,
        "env": {"WIREMOCK_URL": "https://wiremock.example.com", "WIREMOCK_USER": "developer"},
        "capabilities": [
            {"provider": "wiremock", "hosts": ["wiremock.example.com"], "secret": "keychain:x:y"}
        ],
    }))
    box = load_profile_env(resolve_profile("svc"))
    assert box == {
        "WIREMOCK_URL": "https://wiremock.example.com",
        "WIREMOCK_USER": "developer",
    }


def test_the_wiremock_profile_cannot_wipe_the_shared_journal():
    """The admin API is open except where it affects other developers.

    Method is a poor proxy for danger here - `/find` is a read done with POST -
    so the capability allows /__admin/* and denies the handful of endpoints
    that hit everyone sharing the instance.
    """
    from agentsandbox.capabilities import Capability
    from agentsandbox.errors import PolicyDenied

    spec = load_profile(resolve_profile("wiremock"))[0]
    cap = Capability(
        token_hash="0" * 64,
        session_id="s",
        provider=spec.provider,
        hosts=spec.hosts,
        methods=spec.methods,
        path_globs=spec.path_globs,
        deny_path_globs=spec.deny_path_globs,
    )

    # Ordinary admin work is allowed, including the parts that are not reads.
    cap.check_operation("GET", "/__admin/requests")
    cap.check_operation("POST", "/__admin/requests/find")
    cap.check_operation("GET", "/__admin/mappings")
    cap.check_operation("POST", "/__admin/mappings")
    cap.check_operation("POST", "/__admin/requests/remove")  # scoped delete

    for destructive in (
        "/__admin/reset",
        "/__admin/requests/reset",
        "/__admin/mappings/reset",
        "/__admin/shutdown",
    ):
        with pytest.raises(PolicyDenied) as exc:
            cap.check_operation("POST", destructive)
        # `reason` is the stable field; the message is for humans.
        assert exc.value.reason == "path_denied", destructive


def test_the_wiremock_profile_does_not_demand_approval_for_searches():
    """POST /find is a read; blocking it on approval would make it unusable."""
    spec = load_profile(resolve_profile("wiremock"))[0]
    assert spec.approval_required_methods == []
    assert spec.injection.kind == "basic"
    assert spec.injection.username == "developer"


def test_query_strings_do_not_defeat_the_path_check():
    """`?since=...` must not change which path a capability matches."""
    from agentsandbox.capabilities import Capability
    from agentsandbox.errors import PolicyDenied

    spec = load_profile(resolve_profile("wiremock"))[0]
    cap = Capability(
        token_hash="0" * 64,
        session_id="s",
        provider=spec.provider,
        hosts=spec.hosts,
        methods=spec.methods,
        path_globs=spec.path_globs,
        deny_path_globs=spec.deny_path_globs,
    )
    cap.check_operation("GET", "/__admin/requests?since=2026-08-05T00:00:00Z")
    with pytest.raises(PolicyDenied) as exc:
        cap.check_operation("POST", "/__admin/requests/reset?x=1")
    assert exc.value.reason == "path_denied"


def test_a_profile_can_point_at_its_own_pass_store(profile_dir):
    """One project, one password database - said once, not per capability."""
    (profile_dir / "neo.json").write_text(json.dumps({
        "version": 1,
        "pass_store": "~/.password-store-neo",
        "capabilities": [
            {"provider": "a", "hosts": ["a.example.com"], "secret": "pass:wiremock/developer"},
            {"provider": "b", "hosts": ["b.example.com"], "secret": "pass:github/token"},
        ],
    }))
    specs = load_profile(resolve_profile("neo"))
    assert all(s.secret.store == "~/.password-store-neo" for s in specs)
    assert [s.secret.service for s in specs] == ["wiremock/developer", "github/token"]


def test_a_capability_can_override_the_profile_store(profile_dir):
    (profile_dir / "neo.json").write_text(json.dumps({
        "version": 1,
        "pass_store": "~/.password-store-neo",
        "capabilities": [
            {"provider": "a", "hosts": ["a.example.com"], "secret": "pass:wiremock/developer"},
            {
                "provider": "shared",
                "hosts": ["b.example.com"],
                "secret": {"backend": "pass", "service": "github/token", "store": "~/.password-store"},
            },
        ],
    }))
    specs = load_profile(resolve_profile("neo"))
    assert specs[0].secret.store == "~/.password-store-neo"
    assert specs[1].secret.store == "~/.password-store"


@pytest.mark.parametrize(
    "name", [p.stem for p in (Path(profiles.__file__).parent / "_profiles").glob("*.json")]
)
def test_every_shipped_profile_loads(name):
    """A shipped example that does not parse is worse than none: it is the
    thing people copy."""
    specs = load_profile(resolve_profile(name))
    assert specs
    for spec in specs:
        assert spec.hosts and spec.provider
        spec.injection.validate()


def test_a_profile_capability_does_not_expire_by_default():
    """profiles.py had its own hardcoded 3600 and kept it when the default
    changed, so every profile-issued capability still expired after an hour -
    which is every capability anyone actually uses."""
    from agentsandbox.config import DEFAULT_TTL_SECONDS

    for spec in load_profile(resolve_profile("example")):
        if spec.provider == "internal-api":
            assert spec.ttl_seconds == 1800  # explicit, and honoured
        else:
            assert spec.ttl_seconds == DEFAULT_TTL_SECONDS == 0


def test_no_module_hardcodes_a_default_that_config_owns():
    """The same constant in two places is how the TTL change missed profiles.

    cli.py and profiles.py both had their own copies of 3600. Both now import
    from config; this keeps a third from appearing.
    """
    import agentsandbox

    root = Path(agentsandbox.__file__).parent
    offenders = []
    for path in root.rglob("*.py"):
        if path.name == "config.py":
            continue
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            if re.search(r"\b(ttl|max_response_bytes)\w*\s*=.*\b(3600|8 \* 1024 \* 1024)\b", line):
                offenders.append(f"{path.name}:{number}: {line.strip()}")
    assert not offenders, "\n".join(offenders)
