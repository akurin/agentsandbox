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
  and tests with no access to the capability box file.
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

# systemd-networkd-wait-online blocks until every managed link is "routable",
# and a link with no default route never gets there - it stays "degraded". The
# absence of that route is deliberate (see below), so waiting for it is waiting
# for something that is never going to happen: the unit times out after two
# minutes and boot continues anyway.
#
# That matters more than a slow boot. Ubuntu orders cloud-init's later stages
# behind network-online.target, so the two minutes are spent before runcmd -
# and runcmd is what starts the bootstrap that brings up the tunnel. The guest
# looks dead for two minutes for no reason.
[Link]
RequiredForOnline=no

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
    ssh_host_key: str = "",
    ssh_host_pub: str = "",
    ssh_authorized_key: str = "",
) -> str:
    # Checked first, before anything is built. Without the session CA every
    # https call inside the guest fails certificate verification, surfacing as
    # "certificate verify failed" from apt, curl and pip at once - a long way
    # from the empty string that caused it. The caller waits for mitmproxy to
    # write the CA before getting here, so an empty value means that guarantee
    # broke and there is nothing useful to render.
    if not ca_cert.strip():
        raise ValueError(
            "refusing to render cloud-init without a session CA certificate: "
            "the guest would fail every https request"
        )

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
        # Capability placeholders, delivered as environment variables so the agent never
        # hardcodes one. Readable by `agent` alone: `builder` (which runs
        # package installs) cannot see them. These are placeholders, not
        # credentials - they are worthless outside this session.
        # Root-owned here, chowned to agent by the bootstrap. It must NOT name
        # `agent` as the owner at this point: cloud-init runs write_files before
        # users_groups, so the account does not exist yet, the chown fails, and
        # cc_write_files aborts - silently skipping every entry after this one.
        # That took out the sshd unit and the session CA, which are written
        # later in this list, and cost a long time to find because the symptom
        # was a guest with no https and no ssh rather than a file that failed
        # to write.
        _write_file(
            "/run/asbx/capabilities.env",
            "".join(f"export {name}={value}\n" for name, value in sorted((capability_env or {}).items())),
            "0600",
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
    if ssh_host_key and ssh_authorized_key:
        write_files += [
            # sshd binds loopback only; the vsock bridge is the sole way in.
            _write_file(
                "/etc/ssh/sshd_config.d/asbx.conf",
                "ListenAddress 127.0.0.1\n"
                "PermitRootLogin no\n"
                "PasswordAuthentication no\n"
                "KbdInteractiveAuthentication no\n"
                "PubkeyAuthentication yes\n"
                "AllowUsers agent\n"
                "X11Forwarding no\n",
                "0644",
            ),
            _write_file(
                "/etc/systemd/system/asbx-sshd-vsock.service",
                _guest_file("asbx-sshd-vsock.service"),
            ),
        ]

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
        # cloud-init's own log, where the host can read it. Anything that goes
        # wrong in write_files or the earlier stages is recorded there and
        # nowhere else the host can reach - the guest may power itself off
        # before anyone can log in and look.
        ["sh", "-c", "mkdir -p /var/log/asbx && cp /var/log/cloud-init.log /var/log/asbx/cloud-init.log 2>/dev/null || true"],
    ]
    # The operator's way in comes up *before* the bootstrap, not after.
    #
    # cloud-init stops at the first runcmd that fails, so with ssh last, any
    # bootstrap failure took ssh down with it - and the one thing you want when
    # the bootstrap has failed is a shell in the guest to find out why. This
    # ordering costs nothing: sshd listens on loopback and is reachable only
    # over vsock, which the host alone can dial, so it is no more exposed for
    # having started earlier.
    if ssh_host_key and ssh_authorized_key:
        runcmd += [
            ["systemctl", "unmask", "ssh.socket"],
            ["systemctl", "enable", "--now", "ssh.service"],
            ["systemctl", "enable", "--now", "asbx-sshd-vsock.service"],
        ]
    runcmd.append(["/usr/local/bin/asbx-bootstrap"])
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
                # cloud-init owns authorized_keys; writing the file ourselves
                # races its own ssh module.
                "ssh_authorized_keys": [ssh_authorized_key.strip()] if ssh_authorized_key else [],
                # sudoers is written by the bootstrap: root in the guest,
                # plus the drop-down to `builder` for untrusted subprocesses.
                "sudo": None,
                "lock_passwd": True,
            },
            {
                # Package installs and test runs happen here: no sudo, and no
                # read access to the agent's capability box file.
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
    if ssh_host_key and ssh_host_pub:
        # cloud-init defaults to ssh_deletekeys=true: on every new instance-id
        # it deletes the host keys and generates fresh ones, which silently
        # replaced any key we wrote via write_files and made `asbx shell` fail
        # host-key verification. Supplying them here is the supported path -
        # cc_ssh installs exactly these and skips generation.
        payload["ssh_keys"] = {
            "ed25519_private": ssh_host_key,
            "ed25519_public": ssh_host_pub.strip(),
        }
        payload["ssh_deletekeys"] = False
    if netcheck == "halt":
        # cloud-init powers off when the condition command *succeeds*, so
        # netcheck inverts its exit code under this flag: success means "this
        # guest is not fail-closed".
        payload["power_state"] = {
            "mode": "poweroff",
            "condition": ["/usr/local/bin/asbx-netcheck", "--poweroff-condition"],
        }
    return "#cloud-config\n" + json.dumps(payload, indent=2) + "\n"
