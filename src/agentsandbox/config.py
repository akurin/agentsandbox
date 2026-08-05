"""Filesystem layout and tunables for the host side.

Everything the host keeps for a session lives under a single per-session
directory with 0700 permissions.  Nothing in here is ever exposed to the guest:
the guest only ever receives the two files produced by
:mod:`agentsandbox.wireguard` (its own tunnel config) and the session CA
*certificate* (never the key).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

#: Address the guest gets inside the WireGuard tunnel (mitmproxy's wg mode
#: hands out 10.0.0.1/32 and answers DNS on 10.0.0.53).
GUEST_TUNNEL_ADDR = "10.0.0.1"
TUNNEL_DNS_ADDR = "10.0.0.53"

#: Prefix of the placeholder the guest sees instead of a real credential.
CAPABILITY_PREFIX = "cap_v1_"

#: Capabilities do not expire by default: an agent may run unattended for
#: days, and one that dies mid-run fails far from its cause - an HTTP error
#: from a call that worked an hour ago, with nobody present to spot the
#: pattern.  What contains a capability is its *scope*: the host, path and
#: method it is bound to, the session it dies with, and the credential it can
#: never read.  None of that decays with time.  ``--ttl`` remains available
#: for the one thing scope cannot express - a grant narrower than the session,
#: such as thirty minutes of elevated access inside a run lasting days.
DEFAULT_TTL_SECONDS = 0

#: Not a budget: a single response larger than this is *refused*, not
#: truncated, so a runaway download cannot exhaust host memory. Unrelated to
#: how long a capability lives, so it keeps a real value.
DEFAULT_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_REDIRECTS = 3
DEFAULT_UPSTREAM_TIMEOUT = 30.0


#: ``sockaddr_un.sun_path`` is 104 bytes on macOS. Session directories can get
#: long (a deep ``ASBX_HOME``, a long session id), so socket paths fall back to
#: a short per-session directory in the user's private temp area.
MAX_UNIX_SOCKET_PATH = 100


def socket_path(session_id: str, name: str, preferred: Path) -> Path:
    """Return a bindable socket path, shortening it only when it has to."""
    if len(str(preferred)) < MAX_UNIX_SOCKET_PATH:
        return preferred
    return short_run_dir(session_id) / name


def short_run_dir(session_id: str) -> Path:
    """A 0700 directory of ours in ``$TMPDIR``, keyed by session id.

    ``tempfile.gettempdir()`` on macOS is the per-user ``/var/folders/...``
    area, not the shared ``/tmp``, so this stays private. We still verify
    ownership and mode rather than trusting that.
    """
    import hashlib
    import tempfile

    digest = hashlib.sha256(session_id.encode()).hexdigest()[:12]
    path = Path(tempfile.gettempdir()) / f"asbx-{digest}"
    if path.exists():
        st = path.stat()
        if st.st_uid != os.getuid() or st.st_mode & 0o077:
            raise PermissionError(f"refusing to use {path}: not a private directory we own")
    return ensure_private_dir(path)


def home() -> Path:
    """Root of all host-side state. Override with ``ASBX_HOME`` (tests do)."""
    return Path(os.environ.get("ASBX_HOME", Path.home() / ".agentsandbox"))


def ensure_private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def write_private_file(path: Path, content: str | bytes) -> Path:
    """Write a file that only the owner can read, without a readable window.

    The file is created with 0600 from the start (``O_CREAT|O_EXCL`` on a temp
    name, then rename) so a key never exists on disk world-readable.
    """
    ensure_private_dir(path.parent)
    tmp = path.with_name(path.name + ".tmp")
    if tmp.exists():
        tmp.unlink()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(tmp, flags, 0o600)
    try:
        os.write(fd, content.encode() if isinstance(content, str) else content)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    return path


@dataclass(frozen=True)
class SessionPaths:
    """Where a single session keeps its state."""

    session_id: str

    @property
    def root(self) -> Path:
        return home() / "sessions" / self.session_id

    @property
    def mitm_confdir(self) -> Path:
        """Per-session mitmproxy confdir; holds this session's unique CA."""
        return self.root / "mitm"

    @property
    def ca_cert(self) -> Path:
        return self.mitm_confdir / "mitmproxy-ca-cert.pem"

    @property
    def ca_key(self) -> Path:
        """The CA private key. Must never leave the host."""
        return self.mitm_confdir / "mitmproxy-ca.pem"

    @property
    def wireguard_conf(self) -> Path:
        """mitmproxy's wireguard mode config (both private keys)."""
        return self.root / "wg" / "mitm-wireguard.json"

    @property
    def guest_wireguard_conf(self) -> Path:
        """wg-quick config handed to the guest (guest private key only)."""
        return self.root / "wg" / "guest-wg0.conf"

    @property
    def capabilities(self) -> Path:
        return self.root / "capabilities.json"

    @property
    def session_file(self) -> Path:
        return self.root / "session.json"

    @property
    def audit_log(self) -> Path:
        return self.root / "audit.jsonl"

    @property
    def run(self) -> Path:
        """Unix sockets and pid files."""
        return self.root / "run"

    @property
    def broker_socket(self) -> Path:
        return socket_path(self.session_id, "broker.sock", self.run / "broker.sock")

    def forward_socket(self, app_port: int) -> Path:
        name = f"preview-{app_port}.sock"
        return socket_path(self.session_id, name, self.run / name)

    @property
    def guest_net_socket(self) -> Path:
        """The guest's NIC, owned by the host-side L2 gateway."""
        return socket_path(self.session_id, "guest-net.sock", self.run / "guest-net.sock")

    @property
    def broker_token(self) -> Path:
        return self.run / "broker.token"

    @property
    def gateway_stats(self) -> Path:
        """L2 gateway counters, refreshed while a session runs."""
        return self.run / "gateway-stats.json"

    @property
    def guest_logs(self) -> Path:
        """Shared into the guest as /var/log/asbx.

        A guest that powers itself off takes its journal with it, so the few
        things we need for diagnosis - bootstrap output, the netcheck verdict -
        are written here instead, on the host side of a virtio-fs share.
        """
        return self.root / "guest-logs"

    @property
    def vm(self) -> Path:
        return self.root / "vm"

    def create(self) -> None:
        ensure_private_dir(self.root)
        for d in (self.mitm_confdir, self.root / "wg", self.run, self.vm):
            ensure_private_dir(d)


def sessions_root() -> Path:
    return ensure_private_dir(home() / "sessions")
