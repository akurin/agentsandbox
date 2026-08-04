"""Capability profiles: declare once, issue many."""
import json
import pytest
from agentsandbox.errors import CapabilityError
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
