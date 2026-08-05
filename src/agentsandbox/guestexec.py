"""Running one short command inside the guest, from the host side.

``asbx shell`` execs ssh and hands the terminal over.  This is the other case:
the supervisor needs a single command run and its exit status back, without a
terminal and without replacing the process it is running in.

The channel is the same one - ssh over vsock - and that choice is what makes
this usable at all here.  vsock does not go through WireGuard, so it stays up
in exactly the situation this is needed for: the tunnel being down.
"""

from __future__ import annotations

import shlex
import subprocess
import sys
from dataclasses import dataclass

from .errors import SandboxError


@dataclass
class GuestResult:
    """What a guest command did. ``reached`` is the interesting one."""

    #: False means we never got as far as running it - no box, no keys, no
    #: ssh socket. That is a normal state (`asbx session start` has no sshd),
    #: not a failure, and callers are expected to carry on without it.
    reached: bool
    returncode: int = -1
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.reached and self.returncode == 0


def run_in_guest(session, command: str, *, timeout: float = 20.0) -> GuestResult:
    """Run ``command`` in the guest over ssh-on-vsock and return the result.

    Never raises: every way this can fail - no box behind the session, keys
    that were never generated, a guest that is not listening, ssh itself
    timing out - comes back as a :class:`GuestResult` the caller can decide
    about. It is a best-effort side channel, and nothing it is used for is
    allowed to take a session down with it.
    """
    from .box import Box, SshIdentity

    box_name = getattr(session, "box_name", "")
    if not box_name:
        return GuestResult(reached=False, stderr="session has no box, so no sshd")
    try:
        box = Box.load(box_name)
    except SandboxError as exc:
        return GuestResult(reached=False, stderr=str(exc))

    identity = SshIdentity(box.ssh_dir)
    if not identity.exists:
        return GuestResult(reached=False, stderr=f"{box.name} has no ssh keys")

    socket_path = session.paths.run / "ssh.sock"
    if not socket_path.exists():
        return GuestResult(reached=False, stderr=f"no ssh channel at {socket_path}")

    # Same stdio<->unix relay `asbx shell` uses, for the same reason: not
    # depending on which netcat flavour the Mac happens to have.
    proxy = (
        f"{shlex.quote(sys.executable)} -m agentsandbox.cli "
        f"vsock-proxy {shlex.quote(str(socket_path))}"
    )
    identity.write_client_config(box.name, proxy)

    argv = [
        "ssh",
        "-F",
        str(identity.config),
        "-o",
        "BatchMode=yes",  # never sit at a prompt: nobody is watching this one
        "-o",
        f"ConnectTimeout={max(1, int(timeout))}",
        f"asbx-{box.name}",
        "--",
        command,
    ]
    try:
        done = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        return GuestResult(reached=False, stderr=f"ssh to the guest timed out after {timeout:.0f}s")
    except OSError as exc:
        return GuestResult(reached=False, stderr=f"could not run ssh: {exc}")
    return GuestResult(
        reached=True,
        returncode=done.returncode,
        stdout=done.stdout.strip(),
        stderr=done.stderr.strip(),
    )
