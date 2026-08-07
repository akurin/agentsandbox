"""Shared helpers for the real-VM integration suite.

Box lifecycle goes through the actual ``asbx`` CLI as a real subprocess, not
the Python API in-process: `box start`'s supervisor detaches via a fork, and
forking a pytest worker to test that is exactly the kind of thing that looks
fine until it isn't. What's exercised here is precisely what an operator
would type.
"""

from __future__ import annotations

import json
import subprocess
import time
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ASBX = REPO_ROOT / ".venv" / "bin" / "asbx"

#: How long a bootstrap normally takes, plus real margin. Boot itself is
#: seconds; slow apt/network inside the guest is the variable part.
DEFAULT_BOOT_TIMEOUT = 120.0


class AsbxError(RuntimeError):
    def __init__(self, args: tuple[str, ...], result: subprocess.CompletedProcess) -> None:
        self.result = result
        super().__init__(
            f"asbx {' '.join(args)} failed (exit {result.returncode})\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )


def asbx(*args: str, timeout: float = 60, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(
        [str(ASBX), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,  # checked explicitly below, so a non-zero exit carries our own error
    )
    if check and result.returncode != 0:
        raise AsbxError(args, result)
    return result


def new_box_name(prefix: str = "it") -> str:
    """Unique per run, so concurrent or half-cleaned-up runs never collide."""
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def ssh_run(box_name: str, script: str, *, timeout: float = 30) -> subprocess.CompletedProcess:
    """Run a shell script inside the guest, piped over stdin to `bash -s`.

    Passing the command as separate argv entries gets mangled somewhere in
    the ssh/vsock relay - observed directly, a quoted header value split
    into stray positional arguments. Piping a whole script over stdin
    sidesteps quoting entirely.
    """
    return subprocess.run(
        [str(ASBX), "box", "ssh", box_name, "--", "bash", "-s"],
        input=script,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,  # the caller inspects .returncode itself
    )


def current_session(box_name: str):
    """The live (RUNNING) session for a box, read straight from disk state."""
    from agentsandbox.session import STATE_RUNNING, list_sessions

    for session in list_sessions():
        if session.box_name == box_name and session.state == STATE_RUNNING:
            return session
    return None


def wait_for_condition(predicate, *, timeout: float, poll: float = 1.0, description: str) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(poll)
    raise AssertionError(f"timed out after {timeout}s waiting for: {description}")


def wait_for_console(
    session, *, ready: str, timeout: float = DEFAULT_BOOT_TIMEOUT, poll: float = 1.0
) -> str:
    """Poll the guest console log until it contains ``ready``, a bootstrap
    failure marker, or the timeout expires.

    Raises with the console tail attached either way - a bare "timed out"
    with no context is nearly useless for a boot sequence with this many
    moving parts (cloud-init, then a whole systemd unit graph, then the
    bootstrap script itself).
    """
    console = session.paths.vm / "console.log"
    fail_markers = ("FAILED at line", "FATAL")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        text = console.read_text(errors="replace") if console.exists() else ""
        if ready in text:
            return text
        for marker in fail_markers:
            if marker in text:
                raise AssertionError(f"guest bootstrap failed ({marker!r} seen):\n{text[-4000:]}")
        time.sleep(poll)
    text = console.read_text(errors="replace") if console.exists() else "(no console output at all)"
    raise AssertionError(f"timed out after {timeout}s waiting for {ready!r} on the console:\n{text[-4000:]}")


def gateway_stats(session) -> dict:
    """The L2 gateway's live counters.

    Read racily against a writer that has no reason to coordinate with a
    reader - a caller polling this mid-write can see a truncated or empty
    file. That's "not ready yet", the same as the file not existing at all,
    not a real error.
    """
    path = session.paths.gateway_stats
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}


def audit_events(session, event: str | None = None) -> list[dict]:
    from agentsandbox.audit import AuditLog

    records = AuditLog(session.paths.audit_log, session.session_id).read()
    if event is not None:
        records = [r for r in records if r.get("event") == event]
    return records
