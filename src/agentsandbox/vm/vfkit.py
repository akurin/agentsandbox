"""Driving vfkit: one ephemeral Apple Virtualization guest per session.

vfkit is used for exactly three things - boot a disk, attach the NIC to our
unix socket, and expose vsock ports - because everything security-relevant
happens on our side of those interfaces:

* the NIC is a datagram socket owned by :mod:`agentsandbox.vm.gateway`, so the
  guest's only reachable destination is mitmproxy's WireGuard listener;
* vsock is dialled host-to-guest only, which is what makes the preview gateway
  one-directional;
* the disk is a copy-on-write clone of a golden image, so a session starts
  clean and its writes die with it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path

from ..audit import AuditLog, NullAuditLog
from ..config import home, write_private_file
from ..errors import SessionError
from ..session import Session, Share
from .gateway import GatewayConfig, GatewayRunner, guest_network_facts

VFKIT_CANDIDATES = (
    "/opt/podman/bin/vfkit",
    "/opt/homebrew/bin/vfkit",
    "/usr/local/bin/vfkit",
)

GUEST_DIR = Path(__file__).with_name("guest")


def vfkit_path() -> str:
    for candidate in VFKIT_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    found = shutil.which("vfkit")
    if not found:
        raise SessionError(
            "vfkit not found. Install it with `brew install vfkit` "
            "or use the copy shipped with podman."
        )
    return found


def images_dir() -> Path:
    path = home() / "images"
    path.mkdir(parents=True, exist_ok=True)
    return path


def default_golden_image() -> Path:
    return images_dir() / "golden.raw"


@dataclass
class VmConfig:
    """Resources and devices for one guest."""

    cpus: int = 2
    memory_mib: int = 2048
    golden_image: Path = field(default_factory=default_golden_image)
    #: Extra host directories to expose read-only/read-write over virtio-fs.
    shares: list[Share] = field(default_factory=list)
    #: Guest vsock ports to bridge for forwards: {guest_port: unix socket path}
    vsock_ports: dict[int, Path] = field(default_factory=dict)
    #: ``{ENV_VAR: placeholder}`` delivered to the agent as environment.
    #: Placeholders, never credentials - they are useless outside this session.
    capability_env: dict[str, str] = field(default_factory=dict)
    #: When set, boot this disk instead of a per-session clone, and keep it on
    #: teardown. This is what makes an environment's packages survive.
    disk_override: Path | None = None
    efi_override: Path | None = None
    persist_disk: bool = False
    #: SSH key material for `asbx shell`. Without it the guest runs no sshd at
    #: all, which is the right default for a one-off session.
    ssh_host_key: str = ""
    ssh_host_pub: str = ""
    ssh_authorized_key: str = ""
    #: Unix socket vfkit bridges to the guest's sshd vsock port.
    ssh_socket: Path | None = None
    #: "log" writes the guest console to a file; "stdio" attaches it to this
    #: terminal, which is how you get a shell in the guest. There is no SSH
    #: into a session guest by design - the console is the operator's channel,
    #: and it exists only on the host side.
    console: str = "log"
    #: "halt" powers the guest off if it is not fail-closed (the default);
    #: "warn" records the verdict and carries on, which is what you want when
    #: debugging a guest that will not stay up.
    netcheck: str = "halt"


class VfkitDriver:
    """Lifecycle of the guest plus the gateway that keeps it fenced in."""

    def __init__(
        self,
        session: Session,
        vm_config: VmConfig | None = None,
        gateway_config: GatewayConfig | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self.session = session
        self.vm = vm_config or VmConfig(shares=list(session.shares))
        self.gateway_config = gateway_config or GatewayConfig(
            wg_host=session.wg_listen_host, wg_port=session.wg_listen_port
        )
        self.audit = audit or NullAuditLog(session.session_id)
        self.process: subprocess.Popen | None = None
        self.gateway: GatewayRunner | None = None
        self._gateway_thread: threading.Thread | None = None

    # -- paths ---------------------------------------------------------------

    @property
    def vm_dir(self) -> Path:
        return self.session.paths.vm

    @property
    def disk_path(self) -> Path:
        return self.vm.disk_override or (self.vm_dir / "disk.raw")

    @property
    def efi_store(self) -> Path:
        return self.vm.efi_override or (self.vm_dir / "efi-store")

    @property
    def net_socket(self) -> Path:
        # Named for what it is - our gateway's socket - and deliberately not
        # "vmnet", which is the Apple framework we are *not* using.
        return self.session.paths.guest_net_socket

    @property
    def console_log(self) -> Path:
        return self.vm_dir / "console.log"

    @property
    def cloud_init_dir(self) -> Path:
        return self.vm_dir / "cloud-init"

    # -- disk ---------------------------------------------------------------

    def provision_disk(self) -> Path:
        """Make sure a disk exists to boot from.

        For a persistent environment the disk is reused as-is; the guest's
        packages and caches are the whole point of keeping it. Otherwise the
        golden image is cloned with ``cp -c`` (an APFS copy-on-write clone -
        instant, and free until the guest writes).

        Keeping a disk is not a security trade: nothing secret is ever written
        to it. Credentials live in the broker on the host, and capability
        placeholders are injected fresh at every boot.
        """
        if self.vm.persist_disk and self.disk_path.exists():
            return self.disk_path

        golden = Path(self.vm.golden_image)
        if not golden.exists():
            raise SessionError(
                f"golden image {golden} not found - run `make vm-image` first "
                "(see vm/README.md)"
            )
        self.disk_path.parent.mkdir(parents=True, exist_ok=True)
        self.vm_dir.mkdir(parents=True, exist_ok=True)
        if self.disk_path.exists():
            self.disk_path.unlink()
        result = subprocess.run(
            ["/bin/cp", "-c", str(golden), str(self.disk_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:  # not APFS, or cross-volume: fall back
            shutil.copy2(golden, self.disk_path)
        os.chmod(self.disk_path, 0o600)
        return self.disk_path

    # -- guest configuration -------------------------------------------------

    def write_cloud_init(self) -> Path:
        """Render the guest bootstrap with this session's identity.

        Everything the guest needs arrives here: its WireGuard config, the
        session CA *certificate* (never the key), the static network facts, and
        the fail-closed nftables ruleset.
        """
        from .cloudinit import render_user_data

        self.cloud_init_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.cloud_init_dir, 0o700)

        wg_conf = self.session.paths.guest_wireguard_conf
        if not wg_conf.exists():
            raise SessionError("guest wireguard config missing; create the session first")
        # The CA is not optional. Booting without it gives a guest where every
        # https request fails certificate verification, with nothing in the
        # error to suggest the sandbox is the reason.
        ca_cert = self.session.paths.ca_cert
        if not ca_cert.exists() or not ca_cert.read_text().strip():
            raise SessionError(
                f"session CA missing at {ca_cert}; mitmproxy has to be running "
                "before the guest boots, or the guest will trust nothing"
            )

        user_data = render_user_data(
            session=self.session,
            wg_config=wg_conf.read_text(),
            ca_cert=ca_cert.read_text(),
            net=guest_network_facts(self.gateway_config),
            vsock_ports=dict(self.vm.vsock_ports),
            shares=list(self.vm.shares),
            netcheck=self.vm.netcheck,
            capability_env=dict(self.vm.capability_env),
            ssh_host_key=self.vm.ssh_host_key,
            ssh_host_pub=self.vm.ssh_host_pub,
            ssh_authorized_key=self.vm.ssh_authorized_key,
        )
        user_data_path = self.cloud_init_dir / "user-data"
        write_private_file(user_data_path, user_data)
        write_private_file(
            self.cloud_init_dir / "meta-data",
            json.dumps(
                {
                    "instance-id": f"asbx-{self.session.session_id}",
                    "local-hostname": "agent-sandbox",
                }
            ),
        )
        return user_data_path

    # -- argv ---------------------------------------------------------------

    def build_argv(self) -> list[str]:
        argv = [
            vfkit_path(),
            "--cpus",
            str(self.vm.cpus),
            "--memory",
            str(self.vm.memory_mib),
            "--bootloader",
            f"efi,variable-store={self.efi_store},create",
            "--device",
            f"virtio-blk,path={self.disk_path}",
            # The NIC is *our* socket. No NAT device, no vmnet, no bridge:
            # there is no host-provided path to the internet at all.
            "--device",
            f"virtio-net,unixSocketPath={self.net_socket},mac={self.gateway_config.guest_mac}",
            "--device",
            "virtio-rng",
            "--device",
            (
                "virtio-serial,stdio"
                if self.vm.console == "stdio"
                else f"virtio-serial,logFilePath={self.console_log}"
            ),
        ]
        # No --timesync: vfkit's form is `vsockPort=N` and it expects a guest
        # agent listening there, which a session guest does not run. Clock
        # drift after the Mac sleeps is a papercut, not a correctness problem.

        # Guest diagnostics land on the host, so they survive a poweroff.
        self.session.paths.guest_logs.mkdir(parents=True, exist_ok=True)
        argv += [
            "--device",
            f"virtio-fs,sharedDir={self.session.paths.guest_logs},mountTag=asbxlog",
        ]

        for share in self.vm.shares:
            spec = f"virtio-fs,sharedDir={share.path},mountTag={share.tag}"
            if share.read_only:
                spec += ",readOnly"
            argv += ["--device", spec]

        # Host dials in; the guest cannot dial out over these.
        if self.vm.ssh_socket is not None:
            from . import VSOCK_SSH_PORT

            argv += [
                "--device",
                f"virtio-vsock,port={VSOCK_SSH_PORT},socketURL={self.vm.ssh_socket},connect",
            ]
        for guest_port, socket_path in sorted(self.vm.vsock_ports.items()):
            argv += [
                "--device",
                f"virtio-vsock,port={guest_port},socketURL={socket_path},connect",
            ]

        user_data = self.cloud_init_dir / "user-data"
        meta_data = self.cloud_init_dir / "meta-data"
        if user_data.exists():
            argv += ["--cloud-init", str(user_data)]
            # meta-data carries a per-session instance-id. Without it cloud-init
            # sees the same instance every boot and skips the bootstrap, which
            # is a silently broken guest rather than a loud failure.
            if meta_data.exists():
                argv += ["--cloud-init", str(meta_data)]
        return argv

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> subprocess.Popen:
        """Bring up the gateway first, then the guest.

        Order matters: vfkit *dials* the NIC socket at startup and exits if it
        is not there, so the fence is always in place before the guest runs.
        """
        self.provision_disk()
        self.write_cloud_init()

        self.gateway = GatewayRunner(
            self.gateway_config,
            self.net_socket,
            audit=self.audit,
            stats_path=self.session.paths.gateway_stats,
        )
        self.gateway.start()
        self._gateway_thread = self.gateway.run_in_thread()

        argv = self.build_argv()
        if self.vm.console == "stdio":
            # Share the terminal with the guest. Deliberately no setsid here:
            # a new session would detach from the controlling terminal and the
            # guest would never receive what you type.
            self.process = subprocess.Popen(argv)  # noqa: S603 - argv built above
        else:
            fd = os.open(self.vm_dir / "vfkit.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                self.process = subprocess.Popen(  # noqa: S603 - argv built above
                    argv,
                    stdout=fd,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                )
            finally:
                os.close(fd)
        self.audit.emit(
            "vm.started",
            pid=self.process.pid,
            cpus=self.vm.cpus,
            memory_mib=self.vm.memory_mib,
            shares=[f"{s.path}:{'ro' if s.read_only else 'rw'}" for s in self.vm.shares],
            vsock_ports=sorted(self.vm.vsock_ports),
        )
        return self.process

    def is_running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def stop(self, timeout: float = 10.0) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.process = None
        if self.gateway is not None:
            stats = self.gateway.snapshot_stats()
            self.gateway.stop()
            self.gateway = None
            self.audit.emit("vm.stopped", **stats)

    def destroy(self) -> None:
        """Stop the guest, and remove its disk unless it belongs to an environment."""
        self.stop()
        if self.vm.persist_disk:
            # The disk outlives the session by design; the identity and the
            # capabilities that were revoked in `SessionManager.stop` are what
            # actually needed destroying.
            return
        for path in (self.disk_path, self.efi_store):
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
            elif path.exists():
                path.unlink()
