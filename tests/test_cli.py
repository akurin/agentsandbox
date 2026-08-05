"""The argument parser itself.

Not the commands' behaviour - that lives with the subsystems they drive -
but the surface: what is reachable, and what a user can discover from
`asbx --help`.
"""

from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

import pytest

from agentsandbox import cli

def test_every_command_appears_in_the_usage_line():
    """The usage line used to be a hand-written string.

    `asbx set` shipped working but invisible: it was registered, and nothing
    listed it, so the only way to discover it was to read the source. Deriving
    the line from the registered parsers is what stops that recurring - this
    test guards the derivation.
    """
    parser = cli.build_parser()
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))

    listed = set(sub.metavar.strip("{}").split(","))
    registered = set(sub.choices)

    assert listed <= registered, f"usage line names commands that do not exist: {listed - registered}"
    missing = registered - listed - {"vsock-proxy"}
    assert not missing, f"registered but not in the usage line: {missing}"


def test_hidden_commands_stay_out_of_help_entirely():
    """help=SUPPRESS alone leaves a literal '==SUPPRESS==' in the output."""
    parser = cli.build_parser()
    assert "vsock-proxy" in parser._actions[-1].choices  # still callable
    assert "SUPPRESS" not in parser.format_help()
    assert "vsock-proxy" not in parser.format_help()


def test_set_is_reachable_and_wired_up():
    args = cli.build_parser().parse_args(["set", "neo", "--memory", "8192"])
    assert args.func is cli.cmd_box_set
    assert args.name == "neo"
    assert args.memory == 8192


def _build_image(name: str, distro: str, *, prepared: bool = True) -> None:
    """Stand in for ./vm/build-image.sh: a named raw file plus its metadata."""
    import json

    from agentsandbox.vm.vfkit import image_metadata_path, image_path

    image_path(name).write_bytes(b"not a real disk")
    image_metadata_path(name).write_text(
        json.dumps({"name": name, "distro": distro, "prepared": prepared})
    )


def test_doctor_lists_every_built_image_with_its_distro():
    """Which distro is in play is a property of the image a box
    names, so doctor lists what exists rather than asserting one answer."""
    _build_image("ubuntu-24.04", "ubuntu")
    described = " ".join(cli._describe_images())
    assert "debian-13" in described and "debian" in described
    assert "ubuntu-24.04" in described and "ubuntu" in described


def test_an_unprepared_image_is_called_out():
    """An unprepared image boots fine and then fails at the tunnel, with
    nothing on the console explaining why."""
    _build_image("ubuntu-24.04", "ubuntu", prepared=False)
    described = [line for line in cli._describe_images() if "ubuntu" in line]
    assert "not prepared" in described[0]


def test_doctor_says_so_when_nothing_is_built():
    from agentsandbox.vm.vfkit import DEFAULT_IMAGE, image_path

    image_path(DEFAULT_IMAGE).unlink()
    assert "none built" in cli._describe_images()[0]


def test_an_environment_records_the_image_it_was_created_with():
    """The point of the whole thing: `asbx reset` must rebuild from the image
    the box was created with, not from whatever was built last."""
    from agentsandbox.box import Box

    _build_image("ubuntu-24.04", "ubuntu")
    assert cli.main(["create", "on-ubuntu", "--image", "ubuntu-24.04"]) == 0
    assert Box.load("on-ubuntu").image == "ubuntu-24.04"

    # Building another image later must not move it.
    _build_image("debian-14", "debian")
    assert Box.load("on-ubuntu").image == "ubuntu-24.04"


def test_two_environments_can_run_different_images():
    from agentsandbox.box import Box

    _build_image("ubuntu-24.04", "ubuntu")
    assert cli.main(["create", "box-deb"]) == 0
    assert cli.main(["create", "box-ubu", "--image", "ubuntu-24.04"]) == 0
    assert Box.load("box-deb").image == "debian-13"
    assert Box.load("box-ubu").image == "ubuntu-24.04"


def test_creating_on_an_image_that_does_not_exist_is_refused():
    """Otherwise it looks fine until the first start, which fails in vfkit."""
    assert cli.main(["create", "doomed", "--image", "no-such-image"]) == cli.EXIT_USAGE
    from agentsandbox.box import Box

    assert not Box.exists("doomed")


def test_an_environment_created_before_images_were_named_still_starts(asbx_home):
    """Hosts built earlier have an unnamed images/golden.raw and boxes
    with no image field. Both must keep working."""
    from agentsandbox.box import Box
    from agentsandbox.vm.vfkit import DEFAULT_IMAGE, image_path, resolve_image

    image_path(DEFAULT_IMAGE).unlink()
    legacy = asbx_home / "images" / "golden.raw"
    legacy.write_bytes(b"not a real disk")

    box = Box.from_dict({"name": "old"})  # no image key at all
    assert box.image == DEFAULT_IMAGE
    assert resolve_image(box.image) == legacy


def test_diag_collects_the_guest_console():
    """The console is the only log that exists when a guest fails early.

    bootstrap.log and netcheck.log are written by the bootstrap into a
    virtio-fs share; if cloud-init never ran or the share never mounted they
    are absent, and their absence is the symptom, not the explanation. diag
    omitted the console, so a guest that died before bootstrap produced a
    report full of "(missing:" and nothing that said why.
    """
    import inspect

    source = inspect.getsource(cli.cmd_diag)
    assert 'paths.vm / "console.log"' in source
    assert source.index('"guest console"') < source.index('"guest bootstrap"')


def test_start_waits_for_the_ssh_channel_before_reporting_ready():
    """`asbx start box && asbx shell box` must not lose a race with its own
    advice. start prints "asbx shell NAME" as the next step, so it has to be
    true by the time it prints it."""
    import inspect

    source = inspect.getsource(cli._supervise)
    assert source.index("_await_ssh_channel") < source.index("signal_ready()")


def test_waiting_for_the_channel_is_skipped_when_there_is_no_sshd():
    """A one-off session has no ssh socket, and waiting twenty seconds for a
    file that is never coming would be added to every such run."""

    class _NoSsh:
        vm = None

    started = time.monotonic()
    cli._await_ssh_channel(_NoSsh(), timeout=5.0)
    assert time.monotonic() - started < 1.0


def test_waiting_returns_as_soon_as_the_socket_appears(tmp_path):
    class _WithSsh:
        class vm:
            ssh_socket = tmp_path / "ssh.sock"

    (tmp_path / "ssh.sock").write_text("")
    started = time.monotonic()
    cli._await_ssh_channel(_WithSsh(), timeout=5.0)
    assert time.monotonic() - started < 1.0


def test_shell_waits_for_the_sshd_banner_not_just_the_socket():
    """Connecting to ssh.sock proves nothing: vfkit accepts, then fails to
    dial the guest's vsock port and closes. Only the banner means sshd is
    listening - and ssh's own ConnectionAttempts cannot cover the gap, because
    with a ProxyCommand a proxy that exits is fatal rather than retryable.
    That is why `asbx shell` returned instantly with no output at all."""
    import inspect

    source = inspect.getsource(cli._wait_for_sshd)
    assert 'b"SSH-"' in source
    assert "ConnectionAttempts" not in inspect.getsource(cli.cmd_shell)


def test_the_sshd_probe_gives_up_rather_than_hanging(tmp_path):
    started = time.monotonic()
    assert cli._wait_for_sshd(tmp_path / "nothing.sock", timeout=1.0) is False
    assert time.monotonic() - started < 10.0


def test_the_sshd_probe_returns_when_the_banner_arrives(tmp_path):
    import socket
    import threading

    from helpers import unix_sockets_available

    if not unix_sockets_available(tmp_path):
        pytest.skip("outbound unix sockets are blocked in this box")

    path = tmp_path / "ssh.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(1)

    def _greet():
        conn, _ = server.accept()
        conn.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")
        conn.close()

    threading.Thread(target=_greet, daemon=True).start()
    try:
        assert cli._wait_for_sshd(path, timeout=10.0) is True
    finally:
        server.close()


def test_the_wait_message_says_how_long_it_will_wait(tmp_path, capsys):
    """"waiting..." with no bound is indistinguishable from a hang - which is
    exactly what it got asked."""
    cli._wait_for_sshd(tmp_path / "none.sock", timeout=3.0)
    err = capsys.readouterr().err
    assert "up to 3s" in err


def test_diag_falls_back_to_the_most_recent_stopped_session():
    """A guest that fails hard powers itself off, so by the time anyone runs
    diag there is nothing running by definition. Refusing to look is refusing
    exactly when the logs matter most."""
    from agentsandbox.session import STATE_STOPPED, Session

    older = Session(session_id="s-older", state=STATE_STOPPED, created_at=100.0)
    older.save()
    newer = Session(session_id="s-newer", state=STATE_STOPPED, created_at=200.0)
    newer.save()

    assert cli._diag_session(None).session_id == "s-newer"


def test_diag_still_prefers_a_running_session():
    from agentsandbox.session import STATE_RUNNING, STATE_STOPPED, Session

    Session(session_id="s-dead", state=STATE_STOPPED, created_at=300.0).save()
    Session(session_id="s-live", state=STATE_RUNNING, created_at=100.0).save()

    assert cli._diag_session(None).session_id == "s-live"


def test_reachable_is_not_ready(tmp_path):
    """sshd starts before the bootstrap so a failed boot stays debuggable.

    The cost is a window where a shell can be opened into a half-configured
    guest: no tunnel, and capability placeholders still root-owned, so the
    profile script skips the file it cannot read and `env | grep WIREMOCK`
    comes back empty. The marker closes that window.
    """
    import socket
    import threading

    from helpers import unix_sockets_available

    if not unix_sockets_available(tmp_path):
        pytest.skip("outbound unix sockets are blocked in this box")

    path = tmp_path / "ssh.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(8)

    def _greet():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            conn.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")
            conn.close()

    threading.Thread(target=_greet, daemon=True).start()
    try:
        logs = tmp_path / "guest-logs"
        logs.mkdir()
        # sshd answers, but the bootstrap has not finished.
        assert cli._wait_for_sshd(path, timeout=3.0, guest_logs=logs) is False
        (logs / "ready").write_text("2026-08-05T09:00:00Z")
        assert cli._wait_for_sshd(path, timeout=10.0, guest_logs=logs) is True
    finally:
        server.close()


def test_the_bootstrap_writes_the_marker_last():
    """It must mean "everything above succeeded", so it goes after netcheck."""
    text = (
        Path(cli.__file__).parent / "vm" / "guest" / "bootstrap.sh"
    ).read_text()
    assert "/var/log/asbx/ready" in text
    assert text.index("asbx-netcheck") < text.index("/var/log/asbx/ready")


def test_a_finished_bootstrap_log_counts_as_ready(tmp_path):
    """The marker is written with `|| true` so it can never abort a bootstrap
    that otherwise succeeded - which means it can also fail to appear. And a
    guest booted before the marker existed writes the log but not the file.
    Requiring only the marker means waiting the full timeout for something
    that is never coming, on a guest that is fine."""
    logs = tmp_path / "guest-logs"
    logs.mkdir()
    assert cli._guest_is_ready(logs) is False

    (logs / "bootstrap.log").write_text("[asbx-bootstrap] bringing up the tunnel\n")
    assert cli._guest_is_ready(logs) is False

    (logs / "bootstrap.log").write_text(
        "[asbx-bootstrap] bringing up the tunnel\n[asbx-bootstrap] ready\n"
    )
    assert cli._guest_is_ready(logs) is True


def test_a_half_written_bootstrap_log_is_not_ready(tmp_path):
    """A bootstrap that died partway leaves a log without the last line."""
    logs = tmp_path / "guest-logs"
    logs.mkdir()
    (logs / "bootstrap.log").write_text(
        "[asbx-bootstrap] FATAL: no session CA - https would fail for everything\n"
    )
    assert cli._guest_is_ready(logs) is False


def test_stop_waits_for_the_supervisor_to_exit():
    """`asbx stop box && asbx start box` is how anyone restarts a box.

    Returning at the signal made that race the shutdown: start found the
    session still marked running and refused, naming a session that was in the
    middle of exiting.
    """
    import inspect

    source = inspect.getsource(cli.cmd_box_stop)
    assert "_await_supervisor_exit" in source
    assert "args.wait" in source


def test_waiting_returns_immediately_once_the_process_is_gone():
    # A pid that cannot exist: wait should not burn the timeout on it.
    started = time.monotonic()
    assert cli._await_supervisor_exit(2**31 - 1, timeout=5.0) is True
    assert time.monotonic() - started < 1.0


def test_waiting_gives_up_rather_than_hanging():
    started = time.monotonic()
    assert cli._await_supervisor_exit(os.getpid(), timeout=1.0) is False
    assert time.monotonic() - started < 10.0


def test_no_wait_is_available_for_scripts():
    args = cli.build_parser().parse_args(["stop", "neo", "--no-wait"])
    assert args.wait is False
    assert cli.build_parser().parse_args(["stop", "neo"]).wait is True


def test_the_flow_cap_is_loaded_only_in_web_mode():
    """mitmdump keeps no flow list, so it needs no cap. mitmweb keeps every
    flow with its bodies, and left attached for weeks that is unbounded."""
    from agentsandbox.proxy.launcher import VIEWCAP_PATH, build_argv
    from agentsandbox.session import Session

    session = Session(session_id="cap-test")
    assert str(VIEWCAP_PATH) in build_argv(session, web=True)
    assert str(VIEWCAP_PATH) not in build_argv(session, web=False)


def test_attaching_mitmweb_warns_that_it_retains_traffic():
    """Nothing else in the sandbox stores traffic; this mode does, in memory,
    behind a loopback UI anything on the Mac can read."""
    warning = cli._mitmweb_warning()
    assert "memory" in warning
    assert "asbx web detach" in warning


def test_web_attach_and_detach_are_reachable():
    for action in ("attach", "detach"):
        args = cli.build_parser().parse_args(["web", action])
        assert args.func is cli.cmd_web
        assert args.action == action


def test_mitmweb_is_not_a_start_time_flag():
    """One way to do it, and the retaining mode is temporary by construction.

    `--mitmweb` put the whole session into the mode that keeps every flow and
    left it there for the session's life - which for a box meant to run for
    weeks is precisely the shape the warning exists to discourage.
    """
    parser = cli.build_parser()
    for argv in (["start", "neo", "--mitmweb"], ["session", "start", "--mitmweb"]):
        with pytest.raises(SystemExit):
            parser.parse_args(argv)


def test_the_web_port_moved_to_the_command_that_starts_it():
    args = cli.build_parser().parse_args(["web", "attach", "--port", "8081"])
    assert args.action == "attach"
    assert args.port == 8081


def test_removing_an_image_a_box_uses_is_refused():
    """A box that names a deleted image fails at its next reset, which is a
    long way from the command that caused it."""
    from agentsandbox.box import Box
    from agentsandbox.vm.vfkit import DEFAULT_IMAGE, image_path

    Box(name="uses-it", image=DEFAULT_IMAGE).save()
    assert cli.main(["image", "rm", DEFAULT_IMAGE]) == cli.EXIT_USAGE
    assert image_path(DEFAULT_IMAGE).exists()


def test_an_unused_image_is_removed_with_its_metadata():
    from agentsandbox.vm.vfkit import image_metadata_path, image_path

    image_path("spare").write_bytes(b"x" * 1024)
    image_metadata_path("spare").write_text('{"name": "spare"}')

    assert cli.main(["image", "rm", "spare"]) == 0
    assert not image_path("spare").exists()
    assert not image_metadata_path("spare").exists()


def test_force_removes_an_image_still_named(capsys):
    from agentsandbox.box import Box
    from agentsandbox.vm.vfkit import image_path

    image_path("doomed").write_bytes(b"x")
    Box(name="clinger", image="doomed").save()

    assert cli.main(["image", "rm", "doomed", "--force"]) == 0
    assert not image_path("doomed").exists()
    assert "clinger" in capsys.readouterr().out  # says who it just broke


def test_gc_collects_downloads_but_not_the_images_built_from_them(asbx_home):
    """The .qcow2 is only useful for rebuilding the .raw, which is rare - and
    it costs most of a gigabyte until someone notices."""
    from agentsandbox.vm.vfkit import DEFAULT_IMAGE, image_path, images_dir

    (images_dir() / "debian-13-genericcloud-arm64.qcow2").write_bytes(b"x" * 2048)
    (images_dir() / "noble-server-cloudimg-arm64.img").write_bytes(b"x" * 2048)

    assert cli.main(["image", "gc", "--dry-run"]) == 0
    assert (images_dir() / "noble-server-cloudimg-arm64.img").exists()

    assert cli.main(["image", "gc"]) == 0
    assert not (images_dir() / "noble-server-cloudimg-arm64.img").exists()
    assert image_path(DEFAULT_IMAGE).exists()  # the built image is untouched


def test_image_ls_shows_a_name_you_can_actually_type(asbx_home):
    """It displayed the legacy image as "debian-13 (unnamed legacy image)",
    which is not a name `asbx image rm` accepts - the file is golden.raw."""
    from agentsandbox.vm.vfkit import DEFAULT_IMAGE, image_path, list_images

    image_path(DEFAULT_IMAGE).unlink()
    (asbx_home / "images" / "golden.raw").write_bytes(b"x")

    entry = next(i for i in list_images() if "golden" in i["name"])
    assert entry["name"] == "golden"
    assert DEFAULT_IMAGE in entry["note"]
    assert cli.main(["image", "rm", "golden"]) == 0
