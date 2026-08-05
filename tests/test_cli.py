"""The argument parser itself.

Not the commands' behaviour - that lives with the subsystems they drive -
but the surface: what is reachable, and what a user can discover from
`asbx --help`.
"""

from __future__ import annotations

import argparse
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
    marker = tmp_path / "ready"
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
        # sshd answers, but the bootstrap has not finished.
        assert cli._wait_for_sshd(path, timeout=3.0, ready_marker=marker) is False
        marker.write_text("2026-08-05T09:00:00Z")
        assert cli._wait_for_sshd(path, timeout=10.0, ready_marker=marker) is True
    finally:
        server.close()


def test_the_bootstrap_writes_the_marker_last():
    """It must mean "everything above succeeded", so it goes after netcheck."""
    text = (
        Path(cli.__file__).parent / "vm" / "guest" / "bootstrap.sh"
    ).read_text()
    assert "/var/log/asbx/ready" in text
    assert text.index("asbx-netcheck") < text.index("/var/log/asbx/ready")
