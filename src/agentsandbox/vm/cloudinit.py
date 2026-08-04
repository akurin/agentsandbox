"""Rendering the guest's cloud-init bootstrap.

Files are embedded base64-encoded, which sidesteps YAML quoting entirely -
important when the payload is a WireGuard key or a PEM certificate.

What the guest gets, and just as importantly what it does not:

* its own WireGuard private key and the server's public key - **not** the CA
  private key, which never leaves the host;
* the session CA *certificate*, so TLS interception is transparent to tools
  inside the guest;
* a static network configuration with no default route of its own, so the only
  route out is the tunnel;
* two accounts - ``agent`` runs the agent (with root in its own guest, which
  the host-side gateway makes harmless), and ``builder`` runs package installs
  and tests with no access to the capability environment file.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from ..session import Session, Share

GUEST_DIR = Path(__file__).with_name("guest")


def _b64(content: str) -> str:
    return base64.b64encode(content.encode()).decode()


def _guest_file(name: str) -> str:
    return (GUEST_DIR / name).read_text()


def _write_file(path: str, content: str, permissions: str = "0644", owner: str = "root:root") -> dict:
    return {
        "path": path,
        "encoding": "b64",
        "content": _b64(content),
        "permissions": permissions,
        "owner": owner,
    }


def render_network(net: dict) -> str:
    """systemd-networkd unit: static address, no DHCP, no IPv6, no default route.

    Leaving the default route out is deliberate. The only route the guest ever
    gets is the one ``wg-quick`` installs for the tunnel, so an interface that
    comes up before (or instead of) WireGuard routes nowhere.
    """
    address = net["address"]
    return f"""\
[Match]
Name=en*

[Network]
Address={address}
DHCP=no
IPv6AcceptRA=no
LinkLocalAddressing=no
DNS=

# Only the WireGuard endpoint is reachable off-link; everything else must go
# through the tunnel, which wg-quick routes once it is up.
[Route]
Destination={net["gateway"]}/32
Scope=link
"""


def render_user_data(
    *,
    session: Session,
    wg_config: str,
    ca_cert: str,
    net: dict,
    vsock_ports: dict[int, Path] | None = None,
    shares: list[Share] | None = None,
    netcheck: str = "halt",
    capability_env: dict[str, str] | None = None,
) -> str:
    vsock_ports = vsock_ports or {}
    shares = shares or []

    write_files = [
        _write_file("/etc/wireguard/wg0.conf", wg_config, "0600"),
        _write_file("/etc/nftables.conf", _guest_file("nftables.conf"), "0644"),
        _write_file(
            "/etc/systemd/network/10-asbx.network", render_network(net), "0644"
        ),
        _write_file(
            "/etc/sysctl.d/99-asbx.conf",
            "net.ipv6.conf.all.disable_ipv6 = 1\n"
            "net.ipv6.conf.default.disable_ipv6 = 1\n"
            "net.ipv4.ip_forward = 0\n"
            "net.ipv4.conf.all.rp_filter = 1\n",
            "0644",
        ),
        _write_file("/usr/local/bin/asbx-bootstrap", _guest_file("bootstrap.sh"), "0755"),
        _write_file("/usr/local/bin/asbx-netcheck", _guest_file("netcheck.sh"), "0755"),
        _write_file(
            "/usr/local/bin/asbx-forward", _guest_file("forward.sh"), "0755"
        ),
        _write_file(
            "/usr/local/bin/asbx-run-untrusted", _guest_file("run-untrusted.sh"), "0755"
        ),
        _write_file(
            "/etc/systemd/system/asbx-forward@.service", _guest_file("asbx-forward@.service")
        ),
        _write_file(
            "/etc/systemd/system/asbx-netcheck.service", _guest_file("asbx-netcheck.service")
        ),
        # Autologin on the virtio console. The guest has no SSH and no
        # password; the console is the operator's only channel into it, and it
        # is reachable from the host alone - the guest cannot open it outward.
        _write_file(
            "/etc/systemd/system/serial-getty@hvc0.service.d/autologin.conf",
            "[Service]\n"
            "ExecStart=\n"
            "ExecStart=-/sbin/agetty --autologin agent --noclear %I 115200,38400,9600 vt220\n",
        ),
        _write_file("/etc/asbx/netcheck-mode", netcheck + "\n"),
        # Capability placeholders, delivered as environment so the agent never
        # hardcodes one. Readable by `agent` alone: `builder` (which runs
        # package installs) cannot see them. These are placeholders, not
        # credentials - they are worthless outside this session.
        _write_file(
            "/run/asbx/capabilities.env",
            "".join(f"export {name}={value}\n" for name, value in sorted((capability_env or {}).items())),
            "0600",
            "agent:agent",
        ),
        # Sourced by interactive shells so `echo $GITHUB_TOKEN` just works.
        _write_file(
            "/etc/profile.d/asbx-capabilities.sh",
            '[ -r /run/asbx/capabilities.env ] && . /run/asbx/capabilities.env\n',
            "0644",
        ),
        _write_file(
            "/etc/asbx/session.json",
            json.dumps(
                {
                    "session": session.session_id,
                    "shares": [
                        {"tag": s.tag, "read_only": s.read_only, "host_path": s.path}
                        for s in shares
                    ],
                    "forward_ports": sorted(vsock_ports),
                },
                indent=2,
            ),
            "0644",
        ),
    ]
    if ca_cert:
        write_files.append(
            _write_file("/usr/local/share/ca-certificates/asbx-session-ca.crt", ca_cert, "0644")
        )

    # Guest diagnostics go to the host, so a guest that powers itself off still
    # leaves an explanation behind.
    mounts = [["asbxlog", "/var/log/asbx", "virtiofs", "rw,nofail", "0", "0"]]
    for share in shares:
        options = "ro,nofail" if share.read_only else "rw,nofail"
        if share.tag == "project":
            mount_point = session.project_mount or session.project_path or "/workspace"
        else:
            mount_point = f"/mnt/{share.tag}"
        mounts.append([share.tag, mount_point, "virtiofs", options, "0", "0"])

    runcmd = [
        ["systemctl", "daemon-reload"],
        ["systemctl", "restart", "serial-getty@hvc0.service"],
        ["/usr/local/bin/asbx-bootstrap"],
    ]
    # Hand writable mounts to the agent. The mount points are known here, so
    # the guest does not have to work them out for itself.
    for tag, mount_point, _fs, options, *_ in mounts:
        if tag != "asbxlog" and "ro," not in options:
            runcmd.append(["chown", "agent:agent", mount_point])
    for guest_port in sorted(vsock_ports):
        runcmd.append(["systemctl", "enable", "--now", f"asbx-forward@{guest_port}.service"])

    payload = {
        "hostname": "agent-sandbox",
        "users": [
            {
                "name": "agent",
                "shell": "/bin/bash",
                # sudoers is written by the bootstrap: root in the guest,
                # plus the drop-down to `builder` for untrusted subprocesses.
                "sudo": None,
                "lock_passwd": True,
            },
            {
                # Package installs and test runs happen here: no sudo, and no
                # read access to the agent's capability environment file.
                "name": "builder",
                "shell": "/bin/bash",
                "sudo": None,
                "lock_passwd": True,
                "no_user_group": False,
            },
        ],
        "write_files": write_files,
        "mounts": mounts,
        "runcmd": runcmd,
    }
    if netcheck == "halt":
        # cloud-init powers off when the condition command *succeeds*, so
        # netcheck inverts its exit code under this flag: success means "this
        # guest is not fail-closed".
        payload["power_state"] = {
            "mode": "poweroff",
            "condition": ["/usr/local/bin/asbx-netcheck", "--poweroff-condition"],
        }
    return "#cloud-config\n" + json.dumps(payload, indent=2) + "\n"
