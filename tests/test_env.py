"""Environments: the long-lived half of the model.

An environment keeps a disk between runs; a session keeps an identity and a
set of capabilities that die with it. These tests pin that split, because
getting it wrong in either direction is a security or a usability bug.
"""

from __future__ import annotations

import pytest

from agentsandbox import cli
from agentsandbox.env import Environment, default_env_name, list_environments, validate_name
from agentsandbox.errors import SessionError
from agentsandbox.session import Share


@pytest.fixture
def project(tmp_path):
    path = tmp_path / "neo"
    path.mkdir()
    (path / "app.py").write_text("x = 1\n")
    return path


# -- the model ---------------------------------------------------------------


def test_an_environment_round_trips(project):
    env = Environment(
        name="neo",
        project_path=str(project),
        profile="myprofile",
        allow_hosts=["api.github.com"],
        shares=[Share(path=str(project), tag="extra", read_only=True)],
        cpus=4,
    )
    env.save()

    loaded = Environment.load("neo")
    assert loaded.project_path == str(project)
    assert loaded.profile == "myprofile"
    assert loaded.allow_hosts == ["api.github.com"]
    assert loaded.cpus == 4
    assert loaded.shares[0].tag == "extra"


def test_environment_names_are_constrained():
    assert validate_name("My-Env_1") == "my-env_1"
    for bad in ("", "has space", "slash/es", "dots.dots"):
        with pytest.raises(SessionError):
            validate_name(bad)


def test_a_missing_environment_names_the_ones_that_exist():
    Environment(name="alpha").save()
    Environment(name="beta").save()
    with pytest.raises(SessionError) as exc:
        Environment.load("gamma")
    assert "alpha" in str(exc.value) and "beta" in str(exc.value)


def test_default_name_comes_from_the_directory(tmp_path):
    assert default_env_name(tmp_path / "my-project") == "my-project"
    # Anything unusable becomes a dash, and trailing dashes are trimmed.
    assert default_env_name(tmp_path / "Weird Name!") == "weird-name"


def test_rm_takes_the_disk_with_it(project):
    env = Environment(name="neo", project_path=str(project))
    env.save()
    env.disk_path.write_bytes(b"disk")
    assert env.has_disk

    env.delete()
    assert not env.disk_path.exists()
    assert not env.config_path.exists()


def test_rm_can_keep_the_disk(project):
    env = Environment(name="neo")
    env.save()
    env.disk_path.write_bytes(b"disk")

    env.delete(keep_disk=True)
    assert env.disk_path.exists()
    assert not env.config_path.exists()
    env.disk_path.unlink()


def test_reset_drops_the_disk_but_keeps_the_config(project):
    env = Environment(name="neo", project_path=str(project))
    env.save()
    env.disk_path.write_bytes(b"disk")

    env.remove_disk()
    assert not env.has_disk
    assert Environment.load("neo").project_path == str(project)


# -- what persists, and what must not ----------------------------------------


def test_the_disk_survives_a_session_but_the_identity_does_not(project, monkeypatch):
    """The whole point: packages persist, credentials and keys do not."""
    from agentsandbox.manager import SessionManager
    from agentsandbox.vm.vfkit import VfkitDriver, VmConfig

    env = Environment(name="neo", project_path=str(project))
    env.save()
    env.disk_path.write_bytes(b"pretend this is a built disk")

    first = SessionManager.create(allow_hosts=["*"], project=project, env_name="neo")
    driver = VfkitDriver(
        first.session,
        VmConfig(disk_override=env.disk_path, efi_override=env.efi_store, persist_disk=True),
    )
    driver.destroy()

    # The disk is still there for the next run...
    assert env.disk_path.read_bytes() == b"pretend this is a built disk"

    # ...but a second run gets a different tunnel identity.
    second = SessionManager.create(allow_hosts=["*"], project=project, env_name="neo")
    assert (
        first.session.paths.wireguard_conf.read_text()
        != second.session.paths.wireguard_conf.read_text()
    )


def test_an_anonymous_session_still_throws_its_disk_away(session, tmp_path):
    """Without an environment, teardown must delete everything as before."""
    from agentsandbox.vm.vfkit import VfkitDriver, VmConfig

    driver = VfkitDriver(session, VmConfig(persist_disk=False))
    driver.disk_path.parent.mkdir(parents=True, exist_ok=True)
    driver.disk_path.write_bytes(b"throwaway")

    driver.destroy()
    assert not driver.disk_path.exists()


def test_a_persistent_disk_is_not_reclaimed_from_golden(session, tmp_path):
    """An existing environment disk is booted as-is, packages and all."""
    from agentsandbox.vm.vfkit import VfkitDriver, VmConfig

    disk = tmp_path / "neo.raw"
    disk.write_bytes(b"my packages live here")
    driver = VfkitDriver(
        session,
        VmConfig(disk_override=disk, persist_disk=True, golden_image=tmp_path / "absent.raw"),
    )
    # Golden is missing, which would raise if it tried to re-clone.
    assert driver.provision_disk() == disk
    assert disk.read_bytes() == b"my packages live here"


# -- CLI ---------------------------------------------------------------------


def test_cli_create_inspect_and_rm(project, capsys):
    assert cli.main(["create", "neo", "--project", str(project), "--profile", "p"]) == 0
    assert "created" in capsys.readouterr().out

    assert cli.main(["inspect", "neo"]) == 0
    import json

    view = json.loads(capsys.readouterr().out)
    assert view["name"] == "neo"
    assert view["project"] == str(project)
    assert view["disk"] == "(not built yet)"

    assert cli.main(["rm", "neo"]) == 0
    capsys.readouterr()
    assert list_environments() == []


def test_cli_create_refuses_to_clobber(project, capsys):
    assert cli.main(["create", "neo", "--project", str(project)]) == 0
    capsys.readouterr()

    assert cli.main(["create", "neo", "--project", str(project)]) == cli.EXIT_USAGE
    assert "already exists" in capsys.readouterr().err

    assert cli.main(["create", "neo", "--project", str(project), "--force"]) == 0


def test_cli_ls_reports_build_state(project, capsys):
    cli.main(["create", "neo", "--project", str(project)])
    capsys.readouterr()

    assert cli.main(["ls"]) == 0
    assert "not built" in capsys.readouterr().out

    Environment.load("neo").disk_path.write_bytes(b"x")
    assert cli.main(["ls"]) == 0
    assert "stopped" in capsys.readouterr().out


def test_cli_ls_with_nothing_suggests_create(capsys):
    assert cli.main(["ls"]) == 0
    assert "create one" in capsys.readouterr().out
