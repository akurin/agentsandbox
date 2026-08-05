"""Session manager: create everything, and tear all of it down together.

The manager is what makes "destroying a session revokes its network identity
and all capabilities" true.  Start-up order is chosen so the system is never
briefly permissive:

1. session directory and identity (keys, CA dir, capability store)
2. broker (holds the credentials, refuses everything until capabilities exist)
3. mitmproxy (the gateway; without it the guest has nowhere to send packets)
4. L2 gateway and the guest itself

Shutdown runs the same list backwards, and revocation happens *first*, so a
capability cannot outlive the moment we decide to stop.
"""

from __future__ import annotations

import os
import shlex
import signal
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .audit import AuditLog, redactor
from .broker.approvals import AllowAll, ApprovalGate, DenyAll, FileApprovalGate
from .broker.core import BrokerCore
from .broker.server import BrokerServer, issue_token
from .broker.upstream import UpstreamExecutor
from .capabilities import CapabilityStore, CapabilitySpec
from .errors import SessionError
from .keychain import SecretResolver
from .netpolicy import DestinationPolicy
from .proxy.launcher import MitmproxyProcess
from .session import (
    STATE_RUNNING,
    STATE_STOPPED,
    Session,
    Share,
    new_session_id,
    purge_session_dir,
)
from .forward import PortForwarder, TcpDialer, UnixDialer
from .vm import vsock_port_for
from .vm.gateway import GatewayConfig
from .vm.vfkit import VfkitDriver, VmConfig
from .wireguard import WireGuardIdentity

if TYPE_CHECKING:  # pragma: no cover - import cycle at runtime, fine for typing
    from .guestexec import GuestResult


def _free_udp_port(host: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


#: Clear the guest's WireGuard session with the host, and change nothing else.
#:
#: Removing a peer discards its ephemeral keys; adding it back restores the
#: configuration it had, with no session attached. The next packet out of the
#: guest therefore starts a handshake immediately rather than being encrypted
#: under keys the host has already forgotten.
#:
#: The endpoint is read back from the running interface rather than passed in
#: from the host, so this cannot re-add the peer pointing somewhere the guest
#: was not already pointing. And `wg showconf` is captured first: if the re-add
#: fails, the whole interface configuration goes back exactly as it was, because
#: the one outcome worse than a fifteen-second blackout is a guest left with no
#: peer at all.
_REHANDSHAKE = r"""
set -u
conf=$(wg showconf wg0) || exit 2
peer=$(wg show wg0 peers | head -n1)
[ -n "$peer" ] || { echo "wg0 has no peer" >&2; exit 3; }
endpoint=$(wg show wg0 endpoints | head -n1 | cut -f2)
case "$endpoint" in
    ""|"(none)") echo "wg0 peer has no endpoint yet" >&2; exit 4 ;;
esac
wg set wg0 peer "$peer" remove || exit 5
if ! wg set wg0 peer "$peer" endpoint "$endpoint" \
        allowed-ips 0.0.0.0/0 persistent-keepalive 25; then
    printf '%s\n' "$conf" | wg setconf wg0 /dev/stdin
    echo "could not re-add the peer; restored the previous config" >&2
    exit 6
fi
"""


@dataclass
class SessionManager:
    """Owns the processes belonging to one session."""

    session: Session
    audit: AuditLog = field(init=False)
    broker_server: BrokerServer | None = None
    broker_resolver: SecretResolver | None = None
    mitm: MitmproxyProcess | None = None
    vm: VfkitDriver | None = None
    forwards: "ForwardSupervisor | None" = None

    def __post_init__(self) -> None:
        self.audit = AuditLog(self.session.paths.audit_log, self.session.session_id)

    # -- creation -----------------------------------------------------------

    @classmethod
    def create(
        cls,
        *,
        allow_hosts: list[str] | None = None,
        project: Path | None = None,
        project_mount: str = "",
        label: str = "",
        approval_mode: str = "deny",
        shares: list[Share] | None = None,
        wg_listen_host: str = "127.0.0.1",
        wg_listen_port: int | None = None,
        box_name: str = "",
    ) -> SessionManager:
        """Mint a session: fresh identity, fresh CA, direct project mount."""
        project_shares = list(shares or [])
        if project:
            resolved = project.expanduser().resolve()
            if not resolved.is_dir():
                raise SessionError(f"{resolved} is not a directory")
            # Read-write: the agent is meant to edit the project, and the
            # Share default (read-only) is for `--share` extras.
            project_shares.append(Share(path=str(resolved), tag="project", read_only=False))

        session = Session(
            session_id=new_session_id(),
            box_name=box_name,
            label=label,
            policy=DestinationPolicy(allow_hosts=list(allow_hosts or ["*"])),
            approval_mode=approval_mode,
            shares=project_shares,
            wg_listen_host=wg_listen_host,
            wg_listen_port=wg_listen_port or _free_udp_port(wg_listen_host),
            project_path=str(project.expanduser().resolve()) if project else "",
            project_mount=project_mount or (str(project.expanduser().resolve()) if project else ""),
        )
        # Recorded now, not when `start()` finishes: this call already runs
        # inside the process that owns the session for its whole life - the
        # double-forked supervisor, or the CLI itself in `--attach` mode. Not
        # recording it until success meant a session that died on the way to
        # RUNNING (a profile that failed to load, a port `start_proxy` never
        # got) had no pid on file, so `is_alive` read it as dead-and-therefore-
        # startable to check, but `list_sessions()` only ever reconciled
        # STATE_RUNNING - a crashed CREATED session stayed "running" forever.
        session.supervisor_pid = os.getpid()
        session.save()

        identity = WireGuardIdentity.generate(session.wg_listen_host, session.wg_listen_port)
        identity.write_mitm_conf(session.paths.wireguard_conf)
        gateway = GatewayConfig()
        identity.write_guest_config(
            session.paths.guest_wireguard_conf,
            endpoint_host=gateway.gateway_ip,
            endpoint_port=gateway.gateway_port,
        )
        issue_token(session.paths.broker_token)

        manager = cls(session)
        manager.audit.emit(
            "session.created",
            label=label,
            allow_hosts=session.policy.allow_hosts,
            project=session.project_path,
            wg_port=session.wg_listen_port,
        )
        return manager

    # -- components ---------------------------------------------------------

    @property
    def store(self) -> CapabilityStore:
        return CapabilityStore(self.session.paths.capabilities, self.session.session_id)

    def approval_gate(self) -> ApprovalGate:
        mode = self.session.approval_mode
        if mode == "allow":
            return AllowAll()
        if mode == "file":
            return FileApprovalGate(self.session.paths.root / "approvals")
        return DenyAll()

    def build_broker(self, resolver: SecretResolver | None = None) -> BrokerCore:
        return BrokerCore(
            self.session.session_id,
            self.store,
            self.session.policy,
            resolver or SecretResolver(),
            audit=self.audit,
            approvals=self.approval_gate(),
            executor=UpstreamExecutor(self.session.policy),
        )

    def issue_capability(self, spec: CapabilitySpec) -> tuple[str, object]:
        token, cap = self.store.issue(spec)
        self.audit.emit(
            "capability.issued",
            cap_id=cap.cap_id,
            provider=spec.provider,
            hosts=spec.hosts,
            methods=spec.methods,
            ttl_s=spec.ttl_seconds,
        )
        return token, cap

    def issue_from_profile(self, name: str) -> list[tuple[str, object]]:
        """Issue every capability in a named profile. Returns ``[(token, cap), ...]``."""
        from .profiles import load_profile, resolve_profile

        path = resolve_profile(name)
        specs = load_profile(path)
        self.audit.emit("profile.loaded", profile=name, path=str(path), count=len(specs))
        issued: list[tuple[str, object]] = []
        for spec in specs:
            issued.append(self.issue_capability(spec))
        return issued

    # -- lifecycle ----------------------------------------------------------

    def start(
        self,
        *,
        with_vm: bool = True,
        vm_config: VmConfig | None = None,
        resolver: SecretResolver | None = None,
        forward_ports: list[tuple[int, int]] | None = None,
        dev_targets: dict[int, int] | None = None,
        web: bool = False,
        web_port: int = 0,
    ) -> None:
        self.start_broker(resolver)
        self.start_proxy(web=web, web_port=web_port)
        self.start_forwards(forward_ports or [], dev_targets=dev_targets)
        if with_vm:
            config = vm_config or VmConfig(shares=list(self.session.shares))
            if self.forwards is not None:
                # The guest's vsock devices have to exist before it boots.
                config.vsock_ports.update(self.forwards.socket_paths())
            self.start_vm(config)
        self.session.state = STATE_RUNNING
        self.session.supervisor_pid = os.getpid()
        self.session.save()

    def start_broker(self, resolver: SecretResolver | None = None) -> BrokerServer:
        from .broker.server import read_token

        self.broker_resolver = resolver or SecretResolver()
        core = self.build_broker(self.broker_resolver)
        server = BrokerServer(
            core,
            self.session.paths.broker_socket,
            read_token(self.session.paths.broker_token),
            audit=self.audit,
        )
        server.commands["web-attach"] = lambda port: self.reattach_proxy(
            web=True, web_port=int(port or 0)
        )
        server.commands["web-detach"] = lambda _: self.reattach_proxy(web=False)
        server.serve_in_thread()
        self.broker_server = server
        self.session.broker_pid = os.getpid()
        self.audit.emit("broker.started", socket=str(self.session.paths.broker_socket))
        return server

    def reattach_proxy(self, *, web: bool, web_port: int = 0) -> dict:
        """Restart mitmproxy in the other mode, keeping the session's identity.

        Everything the guest depends on lives outside the process: the
        WireGuard keys are a file (``paths.wireguard_conf``), the listen port
        is on the session record, and the CA is in a per-session confdir. So a
        replacement listens on the same port with the same keys and the same
        certificate authority, and the guest's trust store still matches.

        What the replacement does *not* have is the WireGuard session. Those
        keys are ephemeral and lived in the process we just killed, so the
        guest - which has no way to know any of this happened - carries on
        encrypting under a session the new process cannot authenticate, and
        every packet is dropped as noise. WireGuard only notices when its own
        timers run out: KEEPALIVE_TIMEOUT plus REKEY_TIMEOUT, fifteen seconds
        of a tunnel that is up in the guest and dead in fact. `PersistentKeepalive`
        does not help, because those keepalives go out under the dead session too.

        Fifteen seconds is long enough to fail a name lookup - the guest's
        resolver gives up after four - so the first request after an attach or
        a detach used to fail with "Could not resolve host". This clears the
        guest's session instead of waiting for it to expire, and the next
        packet the guest sends handshakes afresh, one round trip.

        What still does not survive is connections in flight. They are reset,
        and anything mid-download sees a broken pipe and has to retry. That is
        the price of not restarting the whole box.
        """
        if self.mitm is not None and self.mitm.web == web:
            return {"ok": True, "message": f"already {'attached' if web else 'detached'}",
                    "url": self.mitm.web_url if web else ""}

        previous = self.mitm
        if previous is not None:
            previous.stop()
            if not self._await_wg_listener(present=False, timeout=5.0):
                raise SessionError(
                    f"the previous mitmproxy is still holding "
                    f"{self.session.wg_listen_host}:{self.session.wg_listen_port}; "
                    f"the replacement could not have the port, so nothing was changed"
                )
        self.start_proxy(web=web, web_port=web_port)
        tunnel = self.renegotiate_tunnel()
        self.audit.emit(
            "proxy.reattached",
            web=web,
            url=self.mitm.web_url if web else "",
            tunnel_renegotiated=tunnel.ok,
        )
        return {
            "ok": True,
            "message": "mitmweb attached" if web else "mitmweb detached",
            "url": self.mitm.web_url if web else "",
            "tunnel": "renegotiated" if tunnel.ok else "waiting for the guest to re-handshake",
        }

    def renegotiate_tunnel(self) -> GuestResult:
        """Drop the guest's WireGuard session so its next packet re-handshakes.

        Removing the peer and putting it back is deliberately narrower than
        ``wg-quick down && wg-quick up``: it throws away the ephemeral keys and
        nothing else. The interface, its routes, the nftables ruleset and the
        resolver configuration the bootstrap put in place all stay exactly as
        they were, and none of them has to be rebuilt correctly a second time.

        Best-effort by design. If the guest cannot be reached - a session with
        no box has no sshd at all - the caller carries on and the guest
        re-handshakes on WireGuard's own timers, which is what it did before.
        """
        from .guestexec import run_in_guest

        result = run_in_guest(
            self.session, f"sudo sh -c {shlex.quote(_REHANDSHAKE)}", timeout=15.0
        )
        if not result.reached:
            self.audit.emit("tunnel.renegotiate_skipped", detail=result.stderr)
        elif not result.ok:
            # Never fatal: the fallback is the fifteen seconds we were trying
            # to avoid, not a broken guest - the script restores the peer it
            # removed if it cannot put it back itself.
            self.audit.emit(
                "tunnel.renegotiate_failed", rc=result.returncode, detail=result.stderr
            )
        else:
            self.audit.emit("tunnel.renegotiated")
        return result

    def start_proxy(self, wait: float = 20.0, *, web: bool = False, web_port: int = 0) -> MitmproxyProcess:
        """Start mitmproxy and wait for it to mint this session's CA.

        Waiting is not optional. The guest is handed the CA certificate through
        cloud-init, which is rendered a few steps later; if we carried on
        before mitmproxy wrote it, the guest would boot with an empty trust
        store and every TLS connection in it would fail with "certificate
        verify failed" - a symptom that points nowhere near the cause.
        """
        mitm = MitmproxyProcess(self.session, web=web, web_port=web_port)
        mitm.start()
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            if mitm.process and mitm.process.poll() is not None:
                log = mitm.log_path.read_text()[-2000:] if mitm.log_path.exists() else ""
                raise SessionError(f"mitmproxy exited during startup:\n{log}")
            if self.session.paths.ca_cert.exists():
                break
            time.sleep(0.2)
        else:
            log = mitm.log_path.read_text()[-2000:] if mitm.log_path.exists() else ""
            mitm.stop()
            raise SessionError(
                f"mitmproxy did not create a CA at {self.session.paths.ca_cert} "
                f"within {wait:.0f}s; refusing to boot a guest that cannot verify "
                f"anything.\n{log}"
            )

        # The CA is not evidence on a *restart*: it was minted by the first
        # start and the file is already there, so the wait above returns on its
        # first pass, before the replacement has bound anything - and without
        # ever reaching the poll() that would notice it had died. Wait for the
        # listener itself, which is the thing the guest actually needs.
        if not self._await_wg_listener(present=True, timeout=wait, mitm=mitm):
            log = mitm.log_path.read_text()[-2000:] if mitm.log_path.exists() else ""
            mitm.stop()
            raise SessionError(
                f"mitmproxy is not listening on "
                f"{self.session.wg_listen_host}:{self.session.wg_listen_port} "
                f"after {wait:.0f}s; the guest would have nowhere to send packets.\n{log}"
            )

        self.mitm = mitm
        self.session.mitm_pid = mitm.pid
        self.session.save()
        self.audit.emit("proxy.started", pid=mitm.pid, port=self.session.wg_listen_port)
        return mitm

    # -- the WireGuard listener, observed from outside -----------------------

    def wg_listener_present(self) -> bool:
        """Is anything holding the session's WireGuard port?

        Asked by binding it ourselves. A UDP socket without ``SO_REUSEPORT``
        cannot share a port with one that has it, so a bind that succeeds means
        the port is genuinely free - and we drop it again immediately, before
        the process that wants it is started.

        This is deliberately about the *port*, not about our child process:
        after a restart, "the old one has let go" and "the new one has taken
        over" are the two facts that matter, and a pid answers neither.
        """
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.bind((self.session.wg_listen_host, self.session.wg_listen_port))
        except OSError:
            return True
        finally:
            probe.close()
        return False

    def _await_wg_listener(
        self, *, present: bool, timeout: float, mitm: MitmproxyProcess | None = None
    ) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if mitm is not None and mitm.process is not None and mitm.process.poll() is not None:
                return False  # it exited; waiting out the timeout tells us nothing more
            if self.wg_listener_present() is present:
                return True
            time.sleep(0.05)
        return False

    def start_forwards(
        self,
        ports: list[tuple[int, int]],
        *,
        dev_targets: dict[int, int] | None = None,
    ) -> dict[int, str]:
        """Expose guest ports at random localhost URLs.

        Ports have to be declared before the guest boots: vfkit attaches vsock
        devices at start-up and cannot hot-plug them, so ``asbx session start
        --preview 3000`` is the only place this can happen.
        """
        if not ports:
            return {}
        supervisor = ForwardSupervisor(self.session, self.audit, dev_targets or {})
        urls = supervisor.start(ports)
        self.forwards = supervisor
        self.session.forwards = {
            str(port): {"url": url, "vsock_port": vsock_port_for(port)}
            for port, url in urls.items()
        }
        self.session.save()
        return urls

    def start_vm(self, vm_config: VmConfig | None = None) -> VfkitDriver:
        config = vm_config or VmConfig(shares=list(self.session.shares))
        driver = VfkitDriver(
            self.session,
            config,
            GatewayConfig(
                wg_host=self.session.wg_listen_host, wg_port=self.session.wg_listen_port
            ),
            audit=self.audit,
        )
        driver.start()
        self.vm = driver
        self.session.vm_pid = driver.process.pid if driver.process else 0
        self.session.save()
        return driver

    # -- teardown -----------------------------------------------------------

    def revoke_all(self) -> int:
        """Kill every capability immediately, before anything else stops."""
        count = self.store.revoke_all()
        self.audit.emit("session.capabilities_revoked", count=count)
        return count

    def stop(self, *, purge: bool = False) -> None:
        """Revoke, then stop, then (optionally) erase.

        Revocation first is not cosmetic: between "stop the VM" and "delete the
        keys" there is a window where an in-flight request could still be
        brokered, and revoking up front closes it.
        """
        # Clear the credential cache first so no in-flight request finds a
        # credential that outlives the session. The Keychain itself holds the
        # truth; this is just the broker's memory of recent fetches.
        if self.broker_resolver is not None:
            self.broker_resolver.clear_cache()
            self.broker_resolver = None
        self.revoke_all()

        if self.forwards is not None:
            self.forwards.stop()
            self.forwards = None

        if self.vm is not None:
            self.vm.destroy()
            self.vm = None
        else:
            _terminate(self.session.vm_pid)

        if self.mitm is not None:
            self.mitm.stop()
            self.mitm = None
        else:
            _terminate(self.session.mitm_pid)

        if self.broker_server is not None:
            self.broker_server.shutdown()
            self.broker_server.server_close()
            self.broker_server = None

        self.session.state = STATE_STOPPED
        self.session.vm_pid = self.session.mitm_pid = self.session.broker_pid = 0
        self.session.save()
        self.audit.emit("session.stopped", purge=purge)

        # Any credential this process unlocked stops being scrubbing-relevant
        # because it stops being in memory.
        redactor.forget_all()

        if purge:
            purge_session_dir(self.session.session_id)

    # -- introspection ------------------------------------------------------

    def status(self) -> dict:
        """Status, whether or not this process is the one running the session.

        ``asbx session status`` usually runs in a second terminal, where there
        are no live process handles - so liveness falls back to the recorded
        pids rather than reporting everything as stopped.
        """
        proxy_alive = bool(self.mitm and self.mitm.process and self.mitm.process.poll() is None)
        vm_alive = bool(self.vm and self.vm.is_running())
        return {
            **self.session.public_view(),
            "capabilities": [c.public_view() for c in self.store.list()],
            "proxy_running": proxy_alive or _is_alive(self.session.mitm_pid),
            "vm_running": vm_alive or _is_alive(self.session.vm_pid),
            "supervisor_running": _is_alive(self.session.supervisor_pid),
            "gateway": (
                self.vm.gateway.snapshot_stats()
                if self.vm and self.vm.gateway
                else _published_gateway_stats(self.session)
            ),
        }


class ForwardSupervisor:
    """Runs the port forwarders on their own asyncio loop, in a thread.

    Each forward is one guest port, one unix socket that vfkit bridges to the
    matching vsock port, and one loopback listener. Nothing is shared between
    forwards, so closing one is just closing its listener.
    """

    def __init__(self, session: Session, audit: AuditLog, dev_targets: dict[int, int]) -> None:
        self.session = session
        self.audit = audit
        self.dev_targets = dev_targets
        self.gateways: dict[int, PortForwarder] = {}
        self._loop = None
        self._thread = None

    def start(self, ports: list[tuple[int, int]]) -> dict[int, str]:
        """``[(host_port, guest_port), ...]`` -> ``{guest_port: url}``."""
        import asyncio
        import threading

        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run_loop, name="asbx-forwards", daemon=True
        )
        self._thread.start()

        urls: dict[int, str] = {}
        for host_port, guest_port in ports:
            if guest_port in self.dev_targets:
                dialer = TcpDialer("127.0.0.1", self.dev_targets[guest_port])
            else:
                dialer = UnixDialer(self.session.paths.forward_socket(guest_port))
            gateway = PortForwarder(
                dialer, guest_port=guest_port, port=host_port, audit=self.audit
            )
            future = asyncio.run_coroutine_threadsafe(gateway.start(), self._loop)
            urls[guest_port] = future.result(timeout=10)
            self.gateways[guest_port] = gateway
        return urls

    def _run_loop(self) -> None:
        import asyncio

        assert self._loop is not None
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def socket_paths(self) -> dict[int, Path]:
        """vsock port -> unix socket, for vfkit's ``virtio-vsock`` devices."""
        return {
            vsock_port_for(port): self.session.paths.forward_socket(port)
            for port in self.gateways
            if port not in self.dev_targets
        }

    def stop(self) -> None:
        import asyncio

        if self._loop is None:
            return
        for gateway in self.gateways.values():
            asyncio.run_coroutine_threadsafe(gateway.stop(), self._loop).result(timeout=5)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self.gateways.clear()
        self._loop = None


def _published_gateway_stats(session: Session) -> dict:
    """Gateway counters as last written by the session's supervisor process."""
    import json

    path = session.paths.gateway_stats
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def _terminate(pid: int, timeout: float = 5.0) -> None:
    """Stop a process we only know by pid (e.g. started by an earlier CLI run)."""
    if pid <= 0:  # never signal pid 0: that is the whole process group
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except PermissionError:
        return
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.1)
    try:
        os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def stop_session_by_id(session_id: str, *, purge: bool = False) -> None:
    """Used by ``asbx session stop`` when the manager is in another process."""
    session = Session.load(session_id)
    manager = SessionManager(session)
    manager.stop(purge=purge)


def kill_orphans() -> list[int]:
    """Best-effort cleanup of mitmdump/vfkit children left by a crashed CLI."""
    killed: list[int] = []
    for session in _running_sessions():
        for pid in (session.vm_pid, session.mitm_pid):
            if pid and _is_alive(pid):
                _terminate(pid)
                killed.append(pid)
    return killed


def _running_sessions() -> list[Session]:
    from .session import list_sessions

    return [s for s in list_sessions() if s.state == STATE_RUNNING]


def _is_alive(pid: int) -> bool:
    """Whether a recorded pid is still running.

    Guarding pid <= 0 matters: ``os.kill(0, sig)`` addresses the caller's whole
    process group, so an unset pid would report "alive" here and, worse, would
    signal every process in the group from :func:`_terminate`.
    """
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError):
        return False
    return True


def check_ipc() -> list[str]:
    """Can this shell actually do the three things a session depends on?

    A sandboxed shell (macOS Seatbelt, some CI runners) can pass every other
    check and then fail at run time in ways that look like bugs: vfkit exits
    because it cannot dial the NIC socket, or the gateway silently relays into
    a loopback connection that was refused. Better to say so up front.
    """
    import socket
    import tempfile

    problems: list[str] = []

    # 1. Unix sockets - how vfkit attaches the guest NIC and how the addon
    #    reaches the broker.
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "probe.sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(str(path))
            server.listen(1)
            client.settimeout(2)
            client.connect(str(path))
        except OSError as exc:
            problems.append(
                f"cannot connect to a unix socket in this shell ({exc.strerror}). "
                "vfkit will not be able to attach the guest NIC - run asbx from a "
                "normal terminal, outside any sandbox wrapper."
            )
        finally:
            server.close()
            client.close()

    # 2. Loopback TCP - how the preview gateway reaches the guest bridge.
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dialer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        dialer.settimeout(2)
        dialer.connect(listener.getsockname())
    except OSError as exc:
        problems.append(
            f"cannot connect to loopback in this shell ({exc.strerror}). "
            "The preview gateway and the WireGuard relay both need it."
        )
    finally:
        listener.close()
        dialer.close()

    # 3. Loopback UDP - how the L2 gateway hands frames to mitmproxy.
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        receiver.bind(("127.0.0.1", 0))
        sender.sendto(b"asbx-probe", receiver.getsockname())
        receiver.settimeout(2)
        receiver.recvfrom(64)
    except OSError as exc:
        problems.append(
            f"cannot send udp to loopback in this shell ({exc.strerror}). "
            "The L2 gateway relays guest WireGuard traffic this way."
        )
    finally:
        sender.close()
        receiver.close()

    return problems


def check_host() -> list[str]:
    """Preflight: report what is missing before a session is attempted."""
    problems: list[str] = []
    from .proxy.launcher import mitmdump_path
    from .vm.vfkit import list_images, vfkit_path

    try:
        mitmdump_path()
    except SessionError as exc:
        problems.append(str(exc))
    try:
        vfkit_path()
    except SessionError as exc:
        problems.append(str(exc))
    # Whether *some* image exists is a host question. Which one a box needs is
    # not: this used to check DEFAULT_IMAGE, so deleting an unused debian-13
    # stopped every box from starting, including ones on another image
    # entirely. The box's own image is checked where the box is known.
    if not list_images():
        problems.append("no base images built - run ./vm/build-image.sh")
    if subprocess.run(["/usr/bin/which", "security"], capture_output=True).returncode != 0:
        problems.append("/usr/bin/security not found: keychain backend unavailable")
    problems.extend(check_ipc())
    return problems
