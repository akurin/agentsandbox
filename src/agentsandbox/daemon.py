"""Detaching the session supervisor, the way conmon does it for podman.

There is no central asbx service. Each running box has one supervisor
process that owns its guest: the vfkit child, the L2 gateway thread, the broker
and the port forwards. The CLI forks it, the supervisor double-forks so it is
re-parented away from the shell, and the CLI returns. Stopping is a signal to
that process, which already knows how to tear everything down in the right
order.

The double fork is what makes it survive your terminal. It does *not* make it
survive a logout or a reboot - that would need a launchd agent, which is a
deliberate next step rather than an accident of process trees.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Callable

#: How the supervisor reports back to the CLI that it came up (or did not).
_READY = b"ready\n"


class StartupFailed(Exception):
    """The supervisor died before it finished starting; carries its message."""


def spawn_supervisor(
    run: Callable[[], None],
    *,
    log_path: Path,
    ready_timeout: float = 180.0,
) -> None:
    """Run ``run()`` in a detached process; return once it reports ready.

    ``run`` is called with a single argument-free convention: it must call
    :func:`signal_ready` as soon as the session is usable, then block until it
    is time to exit. Anything it raises before that point is reported back to
    the caller rather than disappearing into a log nobody reads.

    Raises :class:`StartupFailed` if the supervisor exits or stays silent.
    """
    read_fd, write_fd = os.pipe()

    if os.fork() > 0:  # the CLI
        os.close(write_fd)
        _await_ready(read_fd, ready_timeout)
        return

    # Intermediate child: leave the terminal's session and process group so the
    # supervisor is not killed by a Ctrl-C meant for the shell.
    os.close(read_fd)
    os.setsid()
    if os.fork() > 0:
        os._exit(0)

    # The supervisor itself.
    _redirect_output(log_path)
    os.environ["_ASBX_READY_FD"] = str(write_fd)
    try:
        run()
    except BaseException as exc:  # noqa: BLE001 - last chance to explain itself
        try:
            os.write(write_fd, f"error: {exc}\n".encode()[:4096])
            os.close(write_fd)
        except OSError:
            pass
        os._exit(1)
    os._exit(0)


def signal_ready() -> None:
    """Tell the waiting CLI that the session is up. Safe to call twice."""
    fd = os.environ.pop("_ASBX_READY_FD", None)
    if fd is None:
        return  # running in the foreground; nobody is waiting
    try:
        os.write(int(fd), _READY)
        os.close(int(fd))
    except (OSError, ValueError):
        pass


def _await_ready(read_fd: int, timeout: float) -> None:
    import select

    collected = b""
    deadline = timeout
    while True:
        readable, _, _ = select.select([read_fd], [], [], deadline)
        if not readable:
            os.close(read_fd)
            raise StartupFailed(f"the supervisor did not come up within {timeout:.0f}s")
        chunk = os.read(read_fd, 4096)
        if not chunk:
            os.close(read_fd)
            message = collected.decode(errors="replace").strip()
            raise StartupFailed(message or "the supervisor exited during startup")
        collected += chunk
        if collected.startswith(_READY):
            os.close(read_fd)
            return
        if collected.startswith(b"error:"):
            os.close(read_fd)
            raise StartupFailed(collected.decode(errors="replace").removeprefix("error:").strip())


def _redirect_output(log_path: Path) -> None:
    """Detach from the terminal, keeping a record of whatever gets printed."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    devnull = os.open(os.devnull, os.O_RDONLY)
    sys.stdout.flush()
    sys.stderr.flush()
    os.dup2(devnull, 0)
    os.dup2(fd, 1)
    os.dup2(fd, 2)
    os.close(devnull)
    if fd > 2:
        os.close(fd)
