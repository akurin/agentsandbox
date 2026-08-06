"""Capability profiles: declare once, issue many."""
import json
import re
from pathlib import Path

import pytest
from agentsandbox.errors import CapabilityError
from agentsandbox import profiles
from agentsandbox.profiles import load_profile, load_profile_aws_autosign, resolve_profile, list_profiles

@pytest.fixture
def profile_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("ASBX_PROFILE_DIR", str(tmp_path))
    return tmp_path

def test_json_profile_parses(profile_dir):
    (profile_dir / "oss.json").write_text(json.dumps({
        "version": 1,
        "capabilities": [
            {
                "label": "github",
                "when": {"hosts": ["api.github.com"], "methods": ["GET"]},
                "secret": "keychain:asbx-github:me",
            }
        ],
    }))
    specs = load_profile(resolve_profile("oss"))
    assert len(specs) == 1
    assert specs[0].label == "github"
    assert specs[0].hosts == ["api.github.com"]
    assert specs[0].secret.backend == "keychain"

def test_secret_ref_variants(profile_dir):
    (profile_dir / "s.json").write_text(json.dumps({
        "version": 1,
        "capabilities": [
            {"label": "a", "when": {"hosts": ["x.com"]}, "secret": "keychain:svc:acct"},
            {"label": "b", "when": {"hosts": ["y.com"]}, "secret": {"backend": "env", "name": "TOKEN"}},
        ],
    }))
    specs = load_profile(resolve_profile("s"))
    assert specs[0].secret.backend == "keychain"
    assert specs[0].secret.service == "svc"
    assert specs[0].secret.account == "acct"
    assert specs[1].secret.backend == "env"
    assert specs[1].secret.service == "TOKEN"

def test_secret_ref_dict_form_uses_the_backends_own_field_name(profile_dir):
    """`service` is only the right word for keychain - pass/env/file each get
    their own name (`entry`/`name`/`path`), not one generic field stretched
    over all four."""
    (profile_dir / "s.json").write_text(json.dumps({
        "version": 1,
        "capabilities": [
            {"label": "a", "when": {"hosts": ["x.com"]}, "secret": {"backend": "pass", "entry": "neo/TOKEN"}},
            {"label": "b", "when": {"hosts": ["y.com"]}, "secret": {"backend": "file", "path": "/run/secrets/x"}},
        ],
    }))
    specs = load_profile(resolve_profile("s"))
    assert specs[0].secret.backend == "pass"
    assert specs[0].secret.service == "neo/TOKEN"
    assert specs[1].secret.backend == "file"
    assert specs[1].secret.service == "/run/secrets/x"

def test_secret_ref_dict_form_rejects_the_wrong_backends_field(profile_dir):
    (profile_dir / "bad.json").write_text(json.dumps({
        "version": 1,
        "capabilities": [
            {"label": "a", "when": {"hosts": ["x.com"]}, "secret": {"backend": "pass", "service": "neo/TOKEN"}},
        ],
    }))
    with pytest.raises(CapabilityError, match="'pass' secret needs 'entry'"):
        load_profile(resolve_profile("bad"))

def test_missing_label_is_an_error(profile_dir):
    (profile_dir / "bad.json").write_text(json.dumps({
        "version": 1,
        "capabilities": [{"when": {"hosts": ["x.com"]}, "secret": "keychain:x"}],
    }))
    with pytest.raises(CapabilityError, match="label"):
        load_profile(resolve_profile("bad"))

def test_missing_secret_is_an_error(profile_dir):
    (profile_dir / "bad.json").write_text(json.dumps({
        "version": 1,
        "capabilities": [{"label": "x", "when": {"hosts": ["x.com"]}}],
    }))
    with pytest.raises(CapabilityError, match="secret"):
        load_profile(resolve_profile("bad"))

def test_missing_when_block_is_an_error(profile_dir):
    (profile_dir / "bad.json").write_text(json.dumps({
        "version": 1,
        "capabilities": [{"label": "x", "secret": "keychain:x"}],
    }))
    with pytest.raises(CapabilityError, match="'when' block"):
        load_profile(resolve_profile("bad"))

def test_when_without_hosts_is_an_error(profile_dir):
    (profile_dir / "bad.json").write_text(json.dumps({
        "version": 1,
        "capabilities": [{"label": "x", "when": {"methods": ["GET"]}, "secret": "keychain:x"}],
    }))
    with pytest.raises(CapabilityError, match="when.hosts"):
        load_profile(resolve_profile("bad"))

def test_no_such_profile_is_an_error():
    with pytest.raises(CapabilityError, match="no profile named"):
        resolve_profile("does-not-exist")

def test_list_profiles_includes_builtin_example():
    names = set(list_profiles())
    assert "example" in names

def test_cli_profile_list(capsys):
    from agentsandbox import cli
    assert cli.main(["profile", "ls"]) == 0
    out = capsys.readouterr().out
    assert "example" in out


def test_profiles_can_carry_non_secret_environment(profile_dir):
    """A base URL is configuration, not a credential."""
    from agentsandbox.profiles import load_profile_env

    (profile_dir / "svc.json").write_text(json.dumps({
        "version": 1,
        "env": {"WIREMOCK_URL": "https://wiremock.example.com", "WIREMOCK_USER": "developer"},
        "capabilities": [
            {"label": "wiremock", "when": {"hosts": ["wiremock.example.com"]}, "secret": "keychain:x:y"}
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
        label=spec.label,
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


def test_query_strings_do_not_defeat_the_path_check():
    """`?since=...` must not change which path a capability matches."""
    from agentsandbox.capabilities import Capability
    from agentsandbox.errors import PolicyDenied

    spec = load_profile(resolve_profile("wiremock"))[0]
    cap = Capability(
        token_hash="0" * 64,
        session_id="s",
        label=spec.label,
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
            {"label": "a", "when": {"hosts": ["a.example.com"]}, "secret": "pass:wiremock/developer"},
            {"label": "b", "when": {"hosts": ["b.example.com"]}, "secret": "pass:github/token"},
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
            {"label": "a", "when": {"hosts": ["a.example.com"]}, "secret": "pass:wiremock/developer"},
            {
                "label": "shared",
                "when": {"hosts": ["b.example.com"]},
                "secret": {"backend": "pass", "entry": "github/token", "store": "~/.password-store"},
            },
        ],
    }))
    specs = load_profile(resolve_profile("neo"))
    assert specs[0].secret.store == "~/.password-store-neo"
    assert specs[1].secret.store == "~/.password-store"


def test_username_guest_env_mirrors_the_username_into_plain_env(profile_dir):
    """One value, written once - not duplicated between injection.username.value
    and the profile's own env block."""
    from agentsandbox.profiles import load_profile_env

    (profile_dir / "p.json").write_text(json.dumps({
        "version": 1,
        "capabilities": [{
            "label": "tnb",
            "when": {"hosts": ["x.com"]},
            "secret": "pass:neo/TNB_SECRET",
            "injection": {
                "kind": "basic",
                "username": {"value": "bot@example.com", "guest_env": "TNB_USER"},
            },
        }],
    }))
    assert load_profile_env(resolve_profile("p")) == {"TNB_USER": "bot@example.com"}


def test_username_plain_string_still_works(profile_dir):
    """Most basic-auth capabilities don't need the guest to see the username
    separately - a plain string stays the simple case."""
    (profile_dir / "p.json").write_text(json.dumps({
        "version": 1,
        "capabilities": [{
            "label": "tnb",
            "when": {"hosts": ["x.com"]},
            "secret": "pass:neo/TNB_SECRET",
            "injection": {"kind": "basic", "username": "bot@example.com"},
        }],
    }))
    spec = load_profile(resolve_profile("p"))[0]
    assert spec.injection.username == "bot@example.com"
    assert spec.injection.username_guest_env is None


def test_aws_autosign_parses_the_signing_secret(profile_dir):
    (profile_dir / "p.json").write_text(json.dumps({
        "version": 1,
        "aws_autosign": {
            "signing_secret": {"backend": "keychain", "service": "aws-ci", "account": "deploy"},
        },
        "capabilities": [
            {"label": "x", "when": {"hosts": ["x.com"]}, "secret": "keychain:x"},
        ],
    }))
    autosign = load_profile_aws_autosign(resolve_profile("p"))
    assert autosign is not None
    assert autosign.signing_secret.backend == "keychain"
    assert autosign.signing_secret.service == "aws-ci"
    assert autosign.signing_secret.account == "deploy"
    # Minted per session, never written into the profile.
    assert autosign.access_key_id == ""


def test_aws_autosign_signing_secret_can_be_an_aws_cli_profile(profile_dir):
    """No exported file needed - `aws_profile` resolves live, the same way
    `aws --profile NAME` would, off whatever's already in ~/.aws."""
    (profile_dir / "p.json").write_text(json.dumps({
        "version": 1,
        "aws_autosign": {"signing_secret": {"backend": "aws_profile", "profile": "work"}},
        "capabilities": [{"label": "x", "when": {"hosts": ["x.com"]}, "secret": "keychain:x"}],
    }))
    autosign = load_profile_aws_autosign(resolve_profile("p"))
    assert autosign.signing_secret.backend == "aws_profile"
    assert autosign.signing_secret.service == "work"


def test_aws_autosign_signing_secret_accepts_the_compact_aws_profile_form(profile_dir):
    (profile_dir / "p.json").write_text(json.dumps({
        "version": 1,
        "aws_autosign": {"signing_secret": "aws_profile:work"},
        "capabilities": [{"label": "x", "when": {"hosts": ["x.com"]}, "secret": "keychain:x"}],
    }))
    autosign = load_profile_aws_autosign(resolve_profile("p"))
    assert autosign.signing_secret.backend == "aws_profile"
    assert autosign.signing_secret.service == "work"


def test_a_profile_without_aws_autosign_has_none(profile_dir):
    (profile_dir / "p.json").write_text(json.dumps({
        "version": 1,
        "capabilities": [{"label": "x", "when": {"hosts": ["x.com"]}, "secret": "keychain:x"}],
    }))
    assert load_profile_aws_autosign(resolve_profile("p")) is None


def test_aws_autosign_without_signing_secret_is_an_error(profile_dir):
    (profile_dir / "p.json").write_text(json.dumps({
        "version": 1,
        "aws_autosign": {},
        "capabilities": [{"label": "x", "when": {"hosts": ["x.com"]}, "secret": "keychain:x"}],
    }))
    with pytest.raises(CapabilityError, match="aws_autosign"):
        load_profile_aws_autosign(resolve_profile("p"))


def test_username_guest_env_requires_basic_auth(profile_dir):
    (profile_dir / "p.json").write_text(json.dumps({
        "version": 1,
        "capabilities": [{
            "label": "x", "when": {"hosts": ["x.com"]}, "secret": "keychain:x",
            "injection": {"kind": "bearer", "username": {"guest_env": "X_USER"}},
        }],
    }))
    with pytest.raises(CapabilityError, match="username.guest_env only makes sense for basic auth"):
        load_profile(resolve_profile("p"))


def test_username_guest_env_requires_a_value(profile_dir):
    (profile_dir / "p.json").write_text(json.dumps({
        "version": 1,
        "capabilities": [{
            "label": "x", "when": {"hosts": ["x.com"]}, "secret": "keychain:x",
            "injection": {"kind": "basic", "username": {"guest_env": "X_USER"}},
        }],
    }))
    with pytest.raises(CapabilityError, match="username.guest_env requires username.value"):
        load_profile(resolve_profile("p"))


def test_username_guest_env_colliding_with_the_env_block_is_an_error(profile_dir):
    from agentsandbox.profiles import load_profile_env

    (profile_dir / "p.json").write_text(json.dumps({
        "version": 1,
        "env": {"X_USER": "manual"},
        "capabilities": [{
            "label": "x", "when": {"hosts": ["x.com"]}, "secret": "keychain:x",
            "injection": {"kind": "basic", "username": {"value": "real", "guest_env": "X_USER"}},
        }],
    }))
    with pytest.raises(CapabilityError, match="X_USER"):
        load_profile_env(resolve_profile("p"))


def test_username_guest_env_colliding_with_another_capabilitys_placeholder_is_an_error(profile_dir):
    (profile_dir / "p.json").write_text(json.dumps({
        "version": 1,
        "capabilities": [
            {"label": "a", "when": {"hosts": ["a.com"]}, "secret": "keychain:a", "guest_env": "SHARED"},
            {
                "label": "b", "when": {"hosts": ["b.com"]}, "secret": "keychain:b",
                "injection": {"kind": "basic", "username": {"value": "u", "guest_env": "SHARED"}},
            },
        ],
    }))
    with pytest.raises(CapabilityError, match="SHARED"):
        load_profile(resolve_profile("p"))


def test_two_capabilities_cannot_share_a_placeholder_guest_env(profile_dir):
    """Pre-existing gap, closed by the same collision check: two placeholders
    landing on one guest env var would mean the second silently overwrites
    the first."""
    (profile_dir / "p.json").write_text(json.dumps({
        "version": 1,
        "capabilities": [
            {"label": "a", "when": {"hosts": ["a.com"]}, "secret": "keychain:a", "guest_env": "SHARED"},
            {"label": "b", "when": {"hosts": ["b.com"]}, "secret": "keychain:b", "guest_env": "SHARED"},
        ],
    }))
    with pytest.raises(CapabilityError, match="SHARED"):
        load_profile(resolve_profile("p"))


def test_the_wiremock_example_derives_its_username_guest_env(profile_dir):
    """The shipped example demonstrates the feature by using it to fix its
    own former duplication of WIREMOCK_USER."""
    from agentsandbox.profiles import load_profile_env

    path = Path(profiles.__file__).parent / "_profiles" / "wiremock.json"
    env = load_profile_env(path)
    spec = load_profile(path)[0]
    assert env["WIREMOCK_USER"] == spec.injection.username == "developer"


@pytest.mark.parametrize(
    "name", [p.stem for p in (Path(profiles.__file__).parent / "_profiles").glob("*.json")]
)
def test_every_shipped_profile_loads(name):
    """A shipped example that does not parse is worse than none: it is the
    thing people copy."""
    specs = load_profile(resolve_profile(name))
    assert specs
    for spec in specs:
        assert spec.hosts and spec.label
        spec.injection.validate()


def test_a_profile_capability_does_not_expire_by_default():
    """profiles.py had its own hardcoded 3600 and kept it when the default
    changed, so every profile-issued capability still expired after an hour -
    which is every capability anyone actually uses."""
    from agentsandbox.config import DEFAULT_TTL_SECONDS

    for spec in load_profile(resolve_profile("example")):
        if spec.label == "deploy tooling":
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


def test_profile_show_reveals_what_changes_behaviour(profile_dir, capsys):
    """It used to hide injection, deny_paths and the placeholder name - so the
    fields that decide whether a request succeeds were the ones you could not
    see. label is required now and stands in for what provider used to show,
    so it is expected to appear too."""
    from agentsandbox import cli

    (profile_dir / "p.json").write_text(json.dumps({
        "version": 1,
        "env": {"API_BASE": "https://api.example.com"},
        "capabilities": [{
            "label": "svc",
            "guest_env": "SVC_TOKEN",
            "when": {
                "hosts": ["api.example.com"],
                "methods": ["GET", "POST"],
                "paths": ["/v1/*"],
                "deny_paths": ["/v1/admin/*"],
            },
            "secret": "pass:svc/token",
            "injection": {"kind": "header", "header": "X-Key", "template": "{secret}"},
        }],
    }))
    assert cli.main(["profile", "show", "p"]) == 0
    out = capsys.readouterr().out

    assert "- label: svc" in out          # what identifies this capability
    assert "$SVC_TOKEN" in out            # what the agent actually uses
    assert "X-Key: <secret>" in out       # how it is attached
    assert "/v1/admin/*" in out           # the deny list is a security control
    assert "expires:      never" in out
    assert "API_BASE=https://api.example.com" in out


def test_profile_show_reveals_aws_autosign(profile_dir, capsys):
    from agentsandbox import cli

    (profile_dir / "p.json").write_text(json.dumps({
        "version": 1,
        "aws_autosign": {"signing_secret": "file:/run/secrets/aws.json"},
        "capabilities": [
            {"label": "x", "when": {"hosts": ["x.com"]}, "secret": "keychain:x"},
        ],
    }))
    assert cli.main(["profile", "show", "p"]) == 0
    out = capsys.readouterr().out

    assert "aws_autosign" in out
    assert "$AWS_ACCESS_KEY_ID" in out
    assert "file:/run/secrets/aws.json" in out


def test_profile_show_spells_out_defaults_the_file_omitted():
    """A default is still a decision; the point of the command is to learn
    what will happen, not to see the file read back."""
    from agentsandbox import cli

    assert cli.main(["profile", "show", "example"]) == 0
