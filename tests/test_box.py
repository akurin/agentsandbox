"""Boxes: the long-lived half of the model.

A box keeps a disk between runs; a session keeps an identity and a
set of capabilities that die with it. These tests pin that split, because
getting it wrong in either direction is a security or a usability bug.
"""

from __future__ import annotations

import time

import pytest

from agentsandbox import cli
from agentsandbox.box import Box, default_box_name, list_boxes, validate_name
from agentsandbox.errors import SessionError
from agentsandbox.session import Share


@pytest.fixture
def project(tmp_path):
    path = tmp_path / "neo"
    path.mkdir()
    (path / "app.py").write_text("x = 1\n")
    return path


# -- the model ---------------------------------------------------------------


def test_a_box_round_trips(project):
    box = Box(
        name="neo",
        project_path=str(project),
        profile="myprofile",
        allow_hosts=["api.github.com"],
        shares=[Share(path=str(project), tag="extra", read_only=True)],
        cpus=4,
    )
    box.save()

    loaded = Box.load("neo")
    assert loaded.project_path == str(project)
    assert loaded.profile == "myprofile"
    assert loaded.allow_hosts == ["api.github.com"]
    assert loaded.cpus == 4
    assert loaded.shares[0].tag == "extra"


def test_box_names_are_constrained():
    assert validate_name("My-Env_1") == "my-env_1"
    for bad in ("", "has space", "slash/es", "dots.dots"):
        with pytest.raises(SessionError):
            validate_name(bad)


def test_a_missing_box_names_the_ones_that_exist():
    Box(name="alpha").save()
    Box(name="beta").save()
    with pytest.raises(SessionError) as exc:
        Box.load("gamma")
    assert "alpha" in str(exc.value) and "beta" in str(exc.value)


def test_default_name_comes_from_the_directory(tmp_path):
    assert default_box_name(tmp_path / "my-project") == "my-project"
    # Anything unusable becomes a dash, and trailing dashes are trimmed.
    assert default_box_name(tmp_path / "Weird Name!") == "weird-name"


def test_rm_takes_the_disk_with_it(project):
    box = Box(name="neo", project_path=str(project))
    box.save()
    box.disk_path.write_bytes(b"disk")
    assert box.has_disk

    box.delete()
    assert not box.disk_path.exists()
    assert not box.config_path.exists()


def test_rm_can_keep_the_disk(project):
    box = Box(name="neo")
    box.save()
    box.disk_path.write_bytes(b"disk")

    box.delete(keep_disk=True)
    assert box.disk_path.exists()
    assert not box.config_path.exists()
    box.disk_path.unlink()


def test_reset_drops_the_disk_but_keeps_the_config(project):
    box = Box(name="neo", project_path=str(project))
    box.save()
    box.disk_path.write_bytes(b"disk")

    box.remove_disk()
    assert not box.has_disk
    assert Box.load("neo").project_path == str(project)


# -- what persists, and what must not ----------------------------------------


def test_the_disk_survives_a_session_but_the_identity_does_not(project, monkeypatch):
    """The whole point: packages persist, credentials and keys do not."""
    from agentsandbox.manager import SessionManager
    from agentsandbox.vm.vfkit import VfkitDriver, VmConfig

    box = Box(name="neo", project_path=str(project))
    box.save()
    box.disk_path.write_bytes(b"pretend this is a built disk")

    first = SessionManager.create(allow_hosts=["*"], project=project, box_name="neo")
    driver = VfkitDriver(
        first.session,
        VmConfig(disk_override=box.disk_path, efi_override=box.efi_store, persist_disk=True),
    )
    driver.destroy()

    # The disk is still there for the next run...
    assert box.disk_path.read_bytes() == b"pretend this is a built disk"

    # ...but a second run gets a different tunnel identity.
    second = SessionManager.create(allow_hosts=["*"], project=project, box_name="neo")
    assert (
        first.session.paths.wireguard_conf.read_text()
        != second.session.paths.wireguard_conf.read_text()
    )


def test_an_anonymous_session_still_throws_its_disk_away(session, tmp_path):
    """Without a box, teardown must delete everything as before."""
    from agentsandbox.vm.vfkit import VfkitDriver, VmConfig

    driver = VfkitDriver(session, VmConfig(persist_disk=False))
    driver.disk_path.parent.mkdir(parents=True, exist_ok=True)
    driver.disk_path.write_bytes(b"throwaway")

    driver.destroy()
    assert not driver.disk_path.exists()


def test_a_persistent_disk_is_not_reclaimed_from_golden(session, tmp_path):
    """An existing box disk is booted as-is, packages and all."""
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
    assert list_boxes() == []


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

    Box.load("neo").disk_path.write_bytes(b"x")
    assert cli.main(["ls"]) == 0
    assert "stopped" in capsys.readouterr().out


def test_cli_ls_with_nothing_suggests_create(capsys):
    assert cli.main(["ls"]) == 0
    assert "create one" in capsys.readouterr().out


# -- ssh access --------------------------------------------------------------


def test_each_box_gets_its_own_keys(project):
    """One box's key must not open another's guest."""
    from agentsandbox.box import SshIdentity

    first = Box(name="one")
    first.save()
    second = Box(name="two")
    second.save()

    a, b = SshIdentity(first.ssh_dir), SshIdentity(second.ssh_dir)
    a.generate("one")
    b.generate("two")

    assert a.client_key.read_text() != b.client_key.read_text()
    assert a.host_key.read_text() != b.host_key.read_text()
    # Private keys are owner-only.
    assert a.client_key.stat().st_mode & 0o077 == 0
    assert a.host_key.stat().st_mode & 0o077 == 0


def test_key_generation_is_idempotent(project):
    from agentsandbox.box import SshIdentity

    box = Box(name="neo")
    box.save()
    identity = SshIdentity(box.ssh_dir)
    identity.generate("neo")
    original = identity.client_key.read_text()

    identity.generate("neo")  # again
    assert identity.client_key.read_text() == original


def test_the_ssh_config_pins_the_host_key(project):
    """No trust-on-first-use: a swapped guest must be refused, not accepted."""
    from agentsandbox.box import SshIdentity

    box = Box(name="neo")
    box.save()
    identity = SshIdentity(box.ssh_dir)
    identity.generate("neo")
    identity.write_client_config("neo", "/bin/true")

    config = identity.config.read_text()
    assert "StrictHostKeyChecking yes" in config
    assert str(identity.known_hosts) in config
    assert "IdentitiesOnly yes" in config
    # Agent forwarding off: the guest is untrusted and must not reach host keys.
    assert "ForwardAgent no" in config

    known = identity.known_hosts.read_text()
    assert known.startswith("asbx-neo ssh-ed25519 ")


def test_sshd_in_the_guest_listens_on_loopback_only(session):
    """The vsock bridge is the only way in - nothing binds a network address."""
    import base64
    import json as _json

    from agentsandbox.vm.cloudinit import render_user_data
    from agentsandbox.vm.gateway import GatewayConfig, guest_network_facts
    from agentsandbox.wireguard import WireGuardIdentity

    session.paths.create()
    WireGuardIdentity.generate().write_guest_config(session.paths.guest_wireguard_conf)

    rendered = render_user_data(
        session=session,
        wg_config=session.paths.guest_wireguard_conf.read_text(),
        ca_cert="x",
        net=guest_network_facts(GatewayConfig()),
        ssh_host_key="HOSTKEY",
        ssh_host_pub="HOSTPUB",
        ssh_authorized_key="CLIENTPUB",
    )
    payload = _json.loads(rendered.split("\n", 1)[1])
    files = {
        f["path"]: base64.b64decode(f["content"]).decode() for f in payload["write_files"]
    }

    sshd = files["/etc/ssh/sshd_config.d/asbx.conf"]
    assert "ListenAddress 127.0.0.1" in sshd
    assert "PasswordAuthentication no" in sshd
    assert "PermitRootLogin no" in sshd
    assert "AllowUsers agent" in sshd

    # Host key and authorized_keys go through cloud-init's own ssh handling.
    # Planting them as files loses a race with cc_ssh, which deletes and
    # regenerates host keys on every new instance-id.
    assert payload["ssh_keys"]["ed25519_private"] == "HOSTKEY"
    assert payload["ssh_keys"]["ed25519_public"] == "HOSTPUB"
    assert payload["ssh_deletekeys"] is False
    agent = next(u for u in payload["users"] if u["name"] == "agent")
    assert agent["ssh_authorized_keys"] == ["CLIENTPUB"]

    # And nothing writes those paths directly any more.
    assert "/etc/ssh/ssh_host_ed25519_key" not in files
    assert "/home/agent/.ssh/authorized_keys" not in files


def test_no_sshd_without_keys(session):
    """An anonymous session keeps the smaller surface: console only."""
    import json as _json

    from agentsandbox.vm.cloudinit import render_user_data
    from agentsandbox.vm.gateway import GatewayConfig, guest_network_facts
    from agentsandbox.wireguard import WireGuardIdentity

    session.paths.create()
    WireGuardIdentity.generate().write_guest_config(session.paths.guest_wireguard_conf)

    payload = _json.loads(
        render_user_data(
            session=session,
            wg_config=session.paths.guest_wireguard_conf.read_text(),
            ca_cert="x",
            net=guest_network_facts(GatewayConfig()),
        ).split("\n", 1)[1]
    )
    paths = {f["path"] for f in payload["write_files"]}
    assert not any("ssh" in p for p in paths)


def test_the_ssh_vsock_device_is_connect_only(session, tmp_path):
    """Same direction guarantee as forwards: we dial in, the guest cannot."""
    from agentsandbox.vm.vfkit import VfkitDriver, VmConfig

    driver = VfkitDriver(session, VmConfig(ssh_socket=tmp_path / "ssh.sock"))
    spec = next(a for a in driver.build_argv() if "port=2222" in a)
    assert spec.endswith(",connect")
    assert "listen" not in spec


# -- detached supervisor -----------------------------------------------------


def test_a_detached_supervisor_reports_ready(tmp_path):
    """The CLI must not return until the session is actually usable."""

    from agentsandbox.daemon import signal_ready, spawn_supervisor

    marker = tmp_path / "ran"

    def run():
        marker.write_text("yes")
        signal_ready()

    spawn_supervisor(run, log_path=tmp_path / "sup.log", ready_timeout=20)
    # spawn_supervisor returned, so the child signalled; give the fs a moment.
    for _ in range(100):
        if marker.exists():
            break
        time.sleep(0.05)
    assert marker.read_text() == "yes"


def test_a_supervisor_that_dies_reports_why(tmp_path):
    """A failure during startup must surface, not vanish into a log."""
    from agentsandbox.daemon import StartupFailed, spawn_supervisor

    def run():
        raise RuntimeError("golden image missing")

    with pytest.raises(StartupFailed, match="golden image missing"):
        spawn_supervisor(run, log_path=tmp_path / "sup.log", ready_timeout=20)


def test_a_supervisor_that_never_signals_times_out(tmp_path):
    from agentsandbox.daemon import StartupFailed, spawn_supervisor

    def run():
        time.sleep(30)

    with pytest.raises(StartupFailed, match="did not come up"):
        spawn_supervisor(run, log_path=tmp_path / "sup.log", ready_timeout=1)


def test_starting_an_already_running_box_is_refused(project, capsys, monkeypatch):
    """Two guests would share one disk; vfkit's own error explains nothing."""
    import os

    from agentsandbox.manager import SessionManager
    from agentsandbox.session import STATE_RUNNING

    cli.main(["create", "neo", "--project", str(project)])
    capsys.readouterr()

    manager = SessionManager.create(allow_hosts=["*"], box_name="neo")
    manager.session.state = STATE_RUNNING
    manager.session.supervisor_pid = os.getpid()  # alive
    manager.session.save()

    assert cli.main(["start", "neo"]) == cli.EXIT_USAGE
    err = capsys.readouterr().err
    assert "already running" in err
    assert "asbx shell neo" in err


def test_a_crashed_supervisor_does_not_block_the_box(project, capsys):
    """A session left marked RUNNING by a crash must not wedge it forever."""
    from agentsandbox.cli import _running_session_for
    from agentsandbox.manager import SessionManager
    from agentsandbox.session import STATE_RUNNING, Session

    cli.main(["create", "neo", "--project", str(project)])
    capsys.readouterr()

    manager = SessionManager.create(allow_hosts=["*"], box_name="neo")
    manager.session.state = STATE_RUNNING
    manager.session.supervisor_pid = 999999  # long gone
    manager.session.vm_pid = 0
    manager.session.save()

    assert _running_session_for("neo") is None
    # ...and the stale record is corrected rather than left to confuse.
    assert Session.load(manager.session.session_id).state != STATE_RUNNING


def test_resizing_memory_does_not_touch_the_disk():
    """The obvious worry about `asbx set --memory` is losing the box.

    cpus and memory are vfkit boot arguments; the disk is a separate file, so
    the two cannot interact.
    """
    box = Box(name="resize-me", memory_mib=2048, cpus=2)
    box.save()
    box.disk_path.parent.mkdir(parents=True, exist_ok=True)
    box.disk_path.write_bytes(b"pretend this is a root filesystem")
    before = box.disk_path.read_bytes()

    box.memory_mib = 8192
    box.save()

    reloaded = Box.load("resize-me")
    assert reloaded.memory_mib == 8192
    assert reloaded.cpus == 2
    assert reloaded.disk_path.read_bytes() == before


def test_the_rest_of_the_configuration_survives_a_resize():
    """A resize must not quietly reset anything else it did not ask about."""
    box = Box(
        name="keep-config",
        profile="wiremock",
        allow_hosts=["example.com"],
        approval_mode="file",
        project_path="/some/project",
    )
    box.save()

    box = Box.load("keep-config")
    box.memory_mib = 4096
    box.save()

    reloaded = Box.load("keep-config")
    assert reloaded.profile == "wiremock"
    assert reloaded.allow_hosts == ["example.com"]
    assert reloaded.approval_mode == "file"
    assert reloaded.project_path == "/some/project"
