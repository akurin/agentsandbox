"""Environments: the long-lived half of the model.

A *session* is one boot — it owns the tunnel identity, the CA and the
capabilities, and all three die when it stops.  An *environment* is what you
come back to: a named disk with your packages on it, a project mount, and the
profile that says which credentials the work needs.

The split follows what is actually sensitive.  Nothing secret has ever lived on
the guest disk — credentials stay on the host in the broker, and placeholders
are injected as environment at boot — so keeping the disk between runs costs
nothing security-wise while saving the whole cloud-init package install.

Modelled on ``limactl`` / ``podman machine``: create, start, stop, remove, with
state that survives in between.
"""

from __future__ import annotations

import json
import shutil
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .config import ensure_private_dir, home, write_private_file
from .errors import SessionError
from .session import Share

#: Names are used as filenames and virtio-fs mount tags, so keep them boring.
_NAME_OK = set("abcdefghijklmnopqrstuvwxyz0123456789-_")


def envs_dir() -> Path:
    return ensure_private_dir(home() / "envs")


def disks_dir() -> Path:
    return ensure_private_dir(home() / "disks")


def validate_name(name: str) -> str:
    if not name or not set(name.lower()) <= _NAME_OK:
        raise SessionError(
            f"invalid environment name {name!r}: use letters, digits, '-' and '_'"
        )
    return name.lower()


@dataclass
class Environment:
    """A named, reusable guest. Persisted as JSON; the disk lives beside it."""

    name: str
    created_at: float = field(default_factory=time.time)
    last_started: float = 0.0

    #: Host directory mounted into the guest, at the same absolute path.
    project_path: str = ""
    project_mount: str = ""
    #: Capability profile issued afresh on every start.
    profile: str = ""
    #: Egress policy. ``["*"]`` is any public host; the hard blocks are separate.
    allow_hosts: list[str] = field(default_factory=lambda: ["*"])
    shares: list[Share] = field(default_factory=list)
    approval_mode: str = "deny"

    cpus: int = 2
    memory_mib: int = 2048

    # -- paths --------------------------------------------------------------

    @property
    def config_path(self) -> Path:
        return envs_dir() / f"{self.name}.json"

    @property
    def disk_path(self) -> Path:
        """The persistent disk. Cloned from golden on first start."""
        return disks_dir() / f"{self.name}.raw"

    @property
    def efi_store(self) -> Path:
        return disks_dir() / f"{self.name}.efi"

    @property
    def ssh_dir(self) -> Path:
        """Per-environment SSH keys, so no environment can log into another."""
        return ensure_private_dir(envs_dir() / f"{self.name}.ssh")

    # -- persistence --------------------------------------------------------

    def to_dict(self) -> dict:
        data = asdict(self)
        data["shares"] = [s.to_dict() for s in self.shares]
        return data

    @classmethod
    def from_dict(cls, data: dict) -> Environment:
        data = dict(data)
        data["shares"] = [Share(**s) for s in data.get("shares", [])]
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in data.items() if k in known})

    def save(self) -> None:
        write_private_file(self.config_path, json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls, name: str) -> Environment:
        path = envs_dir() / f"{validate_name(name)}.json"
        if not path.exists():
            known = ", ".join(e.name for e in list_environments()) or "none"
            raise SessionError(f"no environment named {name!r} (have: {known})")
        return cls.from_dict(json.loads(path.read_text()))

    @classmethod
    def exists(cls, name: str) -> bool:
        return (envs_dir() / f"{validate_name(name)}.json").exists()

    def delete(self, *, keep_disk: bool = False) -> None:
        """Remove the environment. The disk goes too unless asked otherwise."""
        if not keep_disk:
            self.remove_disk()
        if self.ssh_dir.exists():
            shutil.rmtree(self.ssh_dir, ignore_errors=True)
        self.config_path.unlink(missing_ok=True)

    def remove_disk(self) -> None:
        """Throw away the guest's filesystem; the next start rebuilds it."""
        self.disk_path.unlink(missing_ok=True)
        if self.efi_store.is_dir():
            shutil.rmtree(self.efi_store, ignore_errors=True)
        else:
            self.efi_store.unlink(missing_ok=True)

    # -- introspection ------------------------------------------------------

    @property
    def has_disk(self) -> bool:
        return self.disk_path.exists()

    def disk_size(self) -> int:
        """Bytes actually used, not the sparse size APFS reports."""
        if not self.has_disk:
            return 0
        return self.disk_path.stat().st_blocks * 512

    def public_view(self) -> dict:
        return {
            "name": self.name,
            "project": self.project_path,
            "mount": self.project_mount or self.project_path,
            "profile": self.profile,
            "allow_hosts": self.allow_hosts,
            "shares": [f"{s.path}:{'ro' if s.read_only else 'rw'}" for s in self.shares],
            "cpus": self.cpus,
            "memory_mib": self.memory_mib,
            "disk": str(self.disk_path) if self.has_disk else "(not built yet)",
            "disk_bytes": self.disk_size(),
            "created_at": self.created_at,
            "last_started": self.last_started,
        }


def list_environments() -> list[Environment]:
    out = []
    for path in sorted(envs_dir().glob("*.json")):
        try:
            out.append(Environment.from_dict(json.loads(path.read_text())))
        except (json.JSONDecodeError, OSError):
            continue
    return out


def default_env_name(project: Path | None = None) -> str:
    """Environment name derived from a project directory, for `asbx up`."""
    base = (project or Path.cwd()).expanduser().resolve().name
    cleaned = "".join(c if c in _NAME_OK else "-" for c in base.lower())
    return cleaned.strip("-") or "default"
