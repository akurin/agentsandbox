"""Boxes: the long-lived half of the model.

A *session* is one boot — it owns the tunnel identity, the CA and the
capabilities, and all three die when it stops.  An *box* is what you
come back to: a named disk with your packages on it, a project mount, and the
profile that says which credentials the work needs.

The split follows what is actually sensitive.  Nothing secret has ever lived on
the guest disk — credentials stay on the host in the broker, and placeholders
are injected as environment variables at boot — so keeping the disk between runs costs
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
from .vm.vfkit import DEFAULT_IMAGE

#: Names are used as filenames and virtio-fs mount tags, so keep them boring.
_NAME_OK = set("abcdefghijklmnopqrstuvwxyz0123456789-_")


def boxes_dir() -> Path:
    return ensure_private_dir(home() / "boxes")


def disks_dir() -> Path:
    return ensure_private_dir(home() / "disks")


def validate_name(name: str) -> str:
    if not name or not set(name.lower()) <= _NAME_OK:
        raise SessionError(
            f"invalid box name {name!r}: use letters, digits, '-' and '_'"
        )
    return name.lower()


@dataclass
class Box:
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

    cpus: int = 2
    memory_mib: int = 2048
    #: Which built image this box's disk is cloned from. Recorded per
    #: box rather than read from a single host-wide file, so `asbx
    #: reset` rebuilds from the same base the box was created with -
    #: and so two boxes can run different distros.
    image: str = DEFAULT_IMAGE

    # -- paths --------------------------------------------------------------

    @property
    def config_path(self) -> Path:
        return boxes_dir() / f"{self.name}.json"

    @property
    def disk_path(self) -> Path:
        """The persistent disk. Cloned from golden on first start."""
        return disks_dir() / f"{self.name}.raw"

    @property
    def efi_store(self) -> Path:
        return disks_dir() / f"{self.name}.efi"

    @property
    def ssh_dir(self) -> Path:
        """Per-box SSH keys, so no box can log into another."""
        return ensure_private_dir(boxes_dir() / f"{self.name}.ssh")

    # -- persistence --------------------------------------------------------

    def to_dict(self) -> dict:
        data = asdict(self)
        data["shares"] = [s.to_dict() for s in self.shares]
        return data

    @classmethod
    def from_dict(cls, data: dict) -> Box:
        data = dict(data)
        data["shares"] = [Share(**s) for s in data.get("shares", [])]
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in data.items() if k in known})

    def save(self) -> None:
        write_private_file(self.config_path, json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls, name: str) -> Box:
        path = boxes_dir() / f"{validate_name(name)}.json"
        if not path.exists():
            known = ", ".join(e.name for e in list_boxes()) or "none"
            raise SessionError(f"no box named {name!r} (have: {known})")
        return cls.from_dict(json.loads(path.read_text()))

    @classmethod
    def exists(cls, name: str) -> bool:
        return (boxes_dir() / f"{validate_name(name)}.json").exists()

    def delete(self, *, keep_disk: bool = False) -> None:
        """Remove the box. The disk goes too unless asked otherwise."""
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
            "image": self.image,
            "disk": str(self.disk_path) if self.has_disk else "(not built yet)",
            "disk_bytes": self.disk_size(),
            "created_at": self.created_at,
            "last_started": self.last_started,
        }


class SshIdentity:
    """The key material that lets the host, and only the host, log in.

    Two keypairs per box, generated once at ``create``:

    * a **host** key, so ``asbx shell`` never sees a host-key prompt and a
      swapped guest would be noticed rather than silently trusted;
    * a **client** key, whose public half goes into the guest's
      ``authorized_keys``. It is per box, so one box's key
      cannot open another's guest.

    Neither is a credential in the broker's sense: they authenticate the
    operator to their own disposable VM, and never leave the host except for
    the two public halves.
    """

    def __init__(self, directory: Path) -> None:
        self.dir = ensure_private_dir(directory)

    @property
    def client_key(self) -> Path:
        return self.dir / "id_ed25519"

    @property
    def host_key(self) -> Path:
        return self.dir / "ssh_host_ed25519_key"

    @property
    def known_hosts(self) -> Path:
        return self.dir / "known_hosts"

    @property
    def config(self) -> Path:
        return self.dir / "config"

    @property
    def exists(self) -> bool:
        return self.client_key.exists() and self.host_key.exists()

    def generate(self, name: str) -> None:
        """Create both keypairs. Idempotent - existing keys are kept."""
        import subprocess

        for path, comment in ((self.client_key, f"asbx-{name}"), (self.host_key, f"asbx-{name}-host")):
            if path.exists():
                continue
            subprocess.run(
                ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(path)],
                check=True,
                capture_output=True,
            )
            path.chmod(0o600)

    def write_client_config(self, name: str, proxy_command: str) -> Path:
        """An ssh_config that reaches this guest and no other.

        Host key checking stays on: the known_hosts file holds exactly the key
        we generated, so a guest presenting anything else is refused rather
        than silently accepted.
        """
        host_pub = self.host_key.with_suffix(".pub").read_text().strip()
        write_private_file(self.known_hosts, f"asbx-{name} {host_pub}\n")

        config = f"""\
# Generated by agentsandbox for box {name!r}.
Host asbx-{name}
    HostName asbx-{name}
    User agent
    IdentityFile {self.client_key}
    IdentitiesOnly yes
    UserKnownHostsFile {self.known_hosts}
    StrictHostKeyChecking yes
    ProxyCommand {proxy_command}
    ForwardAgent no
    LogLevel ERROR
"""
        return write_private_file(self.config, config)


def list_boxes() -> list[Box]:
    out = []
    for path in sorted(boxes_dir().glob("*.json")):
        try:
            out.append(Box.from_dict(json.loads(path.read_text())))
        except (json.JSONDecodeError, OSError):
            continue
    return out


def default_box_name(project: Path | None = None) -> str:
    """Box name derived from a project directory, for `asbx up`."""
    base = (project or Path.cwd()).expanduser().resolve().name
    cleaned = "".join(c if c in _NAME_OK else "-" for c in base.lower())
    return cleaned.strip("-") or "default"
