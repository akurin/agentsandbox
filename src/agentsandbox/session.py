"""Session record: the unit of isolation, revocation and audit.

A session owns a VM, a WireGuard identity, a mitmproxy CA, a capability store
and a mounted project.  Destroying it revokes all of them - that is the whole
point of the object.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .config import SessionPaths, sessions_root, write_private_file
from .errors import SessionError
from .netpolicy import DestinationPolicy

STATE_CREATED = "created"
STATE_RUNNING = "running"
STATE_STOPPED = "stopped"


def new_session_id() -> str:
    """Short, unguessable, filesystem- and log-friendly."""
    return time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)


@dataclass
class Share:
    """An opt-in host directory exposed to the guest over virtio-fs."""

    path: str
    tag: str
    read_only: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Session:
    session_id: str
    created_at: float = field(default_factory=time.time)
    state: str = STATE_CREATED
    label: str = ""

    #: Session-wide egress rules. Empty allowlist = nothing is reachable.
    policy: DestinationPolicy = field(default_factory=DestinationPolicy)

    #: Where mitmproxy's WireGuard server listens, i.e. the guest's only
    #: permitted network destination on the host.
    wg_listen_host: str = "127.0.0.1"
    wg_listen_port: int = 51820

    #: Box this run belongs to, if any. Anonymous sessions have none.
    box_name: str = ""
    #: Host directory mounted into the guest, if any.
    project_path: str = ""
    #: Where the project share mounts inside the guest. Defaults to the host
    #: path so absolute references (virtualenvs, configs) work unchanged.
    project_mount: str = ""

    #: Opt-in virtio-fs shares (the spec's default is *no* mount at all).
    shares: list[Share] = field(default_factory=list)

    #: Preview gateway: guest port -> {"url":..., "vsock_port":..., "token":...}
    forwards: dict[str, dict[str, Any]] = field(default_factory=dict)

    #: "deny" (default), "file" (operator answers via CLI), "allow" (unattended)
    approval_mode: str = "deny"

    vm_pid: int = 0
    mitm_pid: int = 0
    broker_pid: int = 0
    #: The foreground `asbx session start` process; `asbx session stop` signals
    #: it so teardown runs in the process that owns the sockets and threads.
    supervisor_pid: int = 0
    vm_driver: str = "vfkit"

    @property
    def paths(self) -> SessionPaths:
        return SessionPaths(self.session_id)

    # -- persistence --------------------------------------------------------

    def to_dict(self) -> dict:
        data = asdict(self)
        data["policy"] = self.policy.to_dict()
        data["shares"] = [s.to_dict() for s in self.shares]
        return data

    @classmethod
    def from_dict(cls, data: dict) -> Session:
        data = dict(data)
        data["policy"] = DestinationPolicy.from_dict(data.get("policy", {}))
        data["shares"] = [Share(**s) for s in data.get("shares", [])]
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in data.items() if k in known})

    def save(self) -> None:
        self.paths.create()
        write_private_file(self.paths.session_file, json.dumps(self.to_dict(), indent=2))

    @property
    def is_alive(self) -> bool:
        """Is anything actually holding this session up?"""
        return pid_is_alive(self.supervisor_pid) or pid_is_alive(self.vm_pid)

    @classmethod
    def load(cls, session_id: str) -> Session:
        path = SessionPaths(session_id).session_file
        if not path.exists():
            raise SessionError(f"no such session: {session_id}")
        return cls.from_dict(json.loads(path.read_text()))

    # -- introspection ------------------------------------------------------

    def public_view(self) -> dict:
        return {
            "session": self.session_id,
            "state": self.state,
            "label": self.label,
            "age_s": int(time.time() - self.created_at),
            "allow_hosts": self.policy.allow_hosts,
            "project": self.project_path,
            "shares": [f"{s.path}:{'ro' if s.read_only else 'rw'}" for s in self.shares],
            "forwards": {port: p.get("url", "") for port, p in self.forwards.items()},
            "approval_mode": self.approval_mode,
            "wireguard": f"{self.wg_listen_host}:{self.wg_listen_port}",
            "driver": self.vm_driver,
        }


def pid_is_alive(pid: int) -> bool:
    """Whether a recorded pid is still running.

    Guarding pid <= 0 matters: ``os.kill(0, sig)`` addresses the caller's whole
    process group, so an unset pid would report "alive".
    """
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # someone else's now, but it exists
    return True


def list_sessions() -> list[Session]:
    """Every session, with RUNNING reconciled against reality.

    The state on disk is written by a supervisor that may have died without
    getting to write STOPPED - a crash, a SIGKILL, a failed start. Trusting the
    field left sessions marked running forever: they accumulated, `asbx web`
    and `asbx diag` refused with "3 sessions are running - name one", and the
    guard against starting a box twice had to duplicate this check to work at
    all.

    So a session claiming RUNNING with no live supervisor and no live guest is
    corrected here, once, and written back. Reading is the only moment anyone
    is looking.
    """
    out = []
    root = sessions_root()
    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            continue
        try:
            session = Session.load(entry.name)
        except (SessionError, json.JSONDecodeError):
            continue
        if session.state == STATE_RUNNING and not session.is_alive:
            session.state = STATE_STOPPED
            try:
                session.save()
            except OSError:
                pass  # read-only or being torn down; the value is still right
        out.append(session)
    return out


def current_session_id() -> str | None:
    """Session the CLI acts on by default: ``$ASBX_SESSION`` or the newest one."""
    explicit = os.environ.get("ASBX_SESSION")
    if explicit:
        return explicit
    sessions = [s for s in list_sessions() if s.state != STATE_STOPPED]
    if not sessions:
        return None
    return max(sessions, key=lambda s: s.created_at).session_id


def resolve_session_id(explicit: str | None = None) -> str:
    """Which session a command acts on, refusing to guess when it matters.

    With several sessions running, silently picking the newest is how you
    revoke a capability on the wrong project. Ambiguity is an error that names
    the candidates instead.
    """
    if explicit:
        return explicit
    if from_env := os.environ.get("ASBX_SESSION"):
        return from_env

    running = [s for s in list_sessions() if s.state != STATE_STOPPED]
    if len(running) == 1:
        return running[0].session_id
    if len(running) > 1:
        listed = "\n".join(
            f"  {s.session_id}  {s.label or s.project_path or '(no label)'}" for s in running
        )
        raise SessionError(
            f"{len(running)} sessions are running - name one with --session:\n{listed}"
        )

    stopped = list_sessions()
    if stopped:
        raise SessionError(
            f"no session is running ({len(stopped)} stopped). "
            "Use --session <id> to inspect one, or `asbx session list`."
        )
    raise SessionError("no sessions exist; start one with `asbx session start`")


def purge_session_dir(session_id: str) -> None:
    """Remove all host-side state for a session, keys first.

    Key material is overwritten before unlinking; the rest is a plain delete.
    """
    paths = SessionPaths(session_id)
    for secret_file in (
        paths.ca_key,
        paths.wireguard_conf,
        paths.guest_wireguard_conf,
        paths.capabilities,
        paths.broker_token,
    ):
        _shred(secret_file)
    if paths.root.exists():
        shutil.rmtree(paths.root, ignore_errors=True)


def _shred(path: Path) -> None:
    if not path.exists() or not path.is_file():
        return
    try:
        size = path.stat().st_size
        with open(path, "r+b") as fh:
            fh.write(b"\x00" * size)
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        pass
    path.unlink(missing_ok=True)
