"""The guest's configuration: vfkit argv and the cloud-init bootstrap.

None of this can be booted in CI, so it is checked as configuration: the
properties that make the guest fenced in must be visible in the arguments and
in the user-data we hand it.
"""

from __future__ import annotations

import base64
import json

import pytest

FAKE_CA = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"

from agentsandbox.session import Mount
from agentsandbox.vm.cloudinit import render_network, render_user_data
from agentsandbox.vm.gateway import GatewayConfig, guest_network_facts
from agentsandbox.vm.vfkit import VfkitDriver, VmConfig
from agentsandbox.wireguard import WireGuardIdentity


@pytest.fixture
def driver(session, tmp_path):
    session.paths.create()
    identity = WireGuardIdentity.generate(listen_port=51820)
    identity.write_mitm_conf(session.paths.wireguard_conf)
    identity.write_guest_config(session.paths.guest_wireguard_conf, endpoint_host="192.168.127.1")
    session.paths.ca_cert.parent.mkdir(parents=True, exist_ok=True)
    session.paths.ca_cert.write_text(FAKE_CA)
    session.paths.ca_key.write_text("-----BEGIN PRIVATE KEY-----\nCA-SECRET\n-----END PRIVATE KEY-----\n")
    return VfkitDriver(session, VmConfig(), GatewayConfig())


# -- vfkit arguments ---------------------------------------------------------


def test_the_nic_is_our_socket_and_nothing_else(driver):
    argv = " ".join(driver.build_argv())
    assert f"virtio-net,unixSocketPath={driver.net_socket}" in argv
    # No NAT, no vmnet, no bridge: the host offers the guest no other path.
    assert "nat" not in argv
    assert "vmnet" not in argv
    assert "bridge" not in argv


def test_vsock_previews_are_host_dials_in_only(session, driver):
    driver.vm.vsock_ports = {43000: session.paths.run / "preview-3000.sock"}
    argv = driver.build_argv()
    spec = next(a for a in argv if a.startswith("virtio-vsock"))
    assert "port=43000" in spec
    # `connect`, not `listen`: the guest cannot originate connections to us.
    assert spec.endswith(",connect")
    assert "listen" not in spec


def test_read_only_mounts_are_marked_read_only(session, driver, tmp_path):
    shared = tmp_path / "docs"
    shared.mkdir()
    driver.vm.mounts = [
        Mount(host=str(shared), guest="/mnt/docs", read_only=True),
        Mount(host=str(shared), guest="/mnt/scratch", read_only=False),
    ]
    specs = [a for a in driver.build_argv() if a.startswith("virtio-fs")]
    # Tags are positional (m0, m1, ...), not derived from the mount itself.
    assert any("mountTag=m0" in s and s.endswith(",readOnly") for s in specs)
    assert any("mountTag=m1" in s and not s.endswith(",readOnly") for s in specs)


def test_a_mount_is_a_direct_virtio_fs_share(session, driver):
    """A mount is a direct share, not a copy."""
    driver.vm.mounts = [Mount(host="/Users/someone/real-project", guest="/Users/someone/real-project")]
    specs = [a for a in driver.build_argv() if a.startswith("virtio-fs")]
    assert any("sharedDir=/Users/someone/real-project" in s and "mountTag=m0" in s for s in specs)
    # The log share is always present alongside whatever was declared.
    assert any("mountTag=asbxlog" in s for s in specs)


def test_disk_is_per_session(driver, session):
    assert str(session.paths.vm) in str(driver.disk_path)
    assert driver.disk_path.name == "disk.raw"


# -- cloud-init --------------------------------------------------------------


def user_data(session, **kwargs):
    params = {
        "session": session,
        "wg_config": session.paths.guest_wireguard_conf.read_text(),
        "ca_cert": session.paths.ca_cert.read_text(),
        "net": guest_network_facts(GatewayConfig()),
    }
    params.update(kwargs)
    return render_user_data(**params)


def files_in(rendered: str) -> dict[str, str]:
    payload = json.loads(rendered.split("\n", 1)[1])
    return {
        entry["path"]: base64.b64decode(entry["content"]).decode()
        for entry in payload["write_files"]
    }


def test_guest_gets_its_tunnel_config_with_owner_only_permissions(session, driver):
    rendered = user_data(session)
    payload = json.loads(rendered.split("\n", 1)[1])
    wg = next(f for f in payload["write_files"] if f["path"] == "/etc/wireguard/wg0.conf")
    assert wg["permissions"] == "0600"


def test_guest_gets_the_ca_certificate_but_never_the_ca_key(session, driver):
    files = files_in(user_data(session))
    assert "/usr/local/share/ca-certificates/asbx-session-ca.crt" in files
    rendered = user_data(session)
    assert "CA-SECRET" not in rendered
    assert session.paths.ca_key.read_text() not in rendered


def test_guest_gets_the_fail_closed_firewall(session, driver):
    files = files_in(user_data(session))
    nft = files["/etc/nftables.conf"]
    assert "policy drop" in nft
    assert "udp dport $WG_PORT accept" in nft


def test_package_installs_run_as_a_less_privileged_account(session, driver):
    rendered = user_data(session)
    payload = json.loads(rendered.split("\n", 1)[1])
    names = {u["name"] for u in payload["users"]}
    assert {"agent", "builder"} <= names
    assert all(u.get("sudo") is None for u in payload["users"])

    files = files_in(rendered)
    runner = files["/usr/local/bin/asbx-run-untrusted"]
    assert "sudo -u builder" in runner
    assert "env -i" in runner  # the environment is scrubbed, not filtered

    bootstrap = files["/usr/local/bin/asbx-bootstrap"]
    assert "agent ALL=(builder) NOPASSWD: ALL" in bootstrap
    # Capability placeholders are readable by the agent alone.
    assert "chmod 0600 /run/asbx/capabilities.env" in bootstrap


def test_ipv6_is_disabled_in_the_guest(session, driver):
    files = files_in(user_data(session))
    assert "net.ipv6.conf.all.disable_ipv6 = 1" in files["/etc/sysctl.d/99-asbx.conf"]


def test_the_static_network_has_no_default_route():
    """Only wg-quick may install a default route."""
    config = render_network(guest_network_facts(GatewayConfig()))
    assert "Gateway=" not in config
    assert "DHCP=no" in config
    assert "Scope=link" in config


def test_mounts_are_mounted_with_the_mode_they_were_granted(session, driver, tmp_path):
    shared = tmp_path / "docs"
    shared.mkdir()
    rendered = user_data(
        session, mounts=[Mount(host=str(shared), guest="/mnt/docs", read_only=True)]
    )
    payload = json.loads(rendered.split("\n", 1)[1])
    docs = next(m for m in payload["mounts"] if m[0] == "m0")
    assert docs[1] == "/mnt/docs"
    assert "ro" in docs[3]


def test_preview_units_are_enabled_for_declared_ports(session, driver):
    rendered = user_data(session, vsock_ports={43000: "/tmp/x.sock"})
    payload = json.loads(rendered.split("\n", 1)[1])
    assert ["systemctl", "enable", "--now", "asbx-forward@43000.service"] in payload["runcmd"]


def test_guest_powers_itself_off_if_it_is_not_fail_closed(session, driver):
    rendered = user_data(session)  # netcheck defaults to halt
    payload = json.loads(rendered.split("\n", 1)[1])
    assert payload["power_state"]["mode"] == "poweroff"
    assert payload["power_state"]["condition"] == [
        "/usr/local/bin/asbx-netcheck",
        "--poweroff-condition",
    ]
    netcheck = files_in(rendered)["/usr/local/bin/asbx-netcheck"]
    assert 'egress_dev" != "wg0"' in netcheck


def test_console_mode_attaches_the_terminal(session, driver):
    """`--console` is the only way into a session guest: no SSH, no password."""
    driver.vm.console = "stdio"
    argv = driver.build_argv()
    assert "virtio-serial,stdio" in argv
    assert not any("logFilePath" in a for a in argv)

    driver.vm.console = "log"
    argv = driver.build_argv()
    assert any(a.startswith("virtio-serial,logFilePath=") for a in argv)


def test_the_console_autologs_in_as_the_agent(session, driver):
    files = files_in(user_data(session))
    override = files["/etc/systemd/system/serial-getty@hvc0.service.d/autologin.conf"]
    assert "--autologin agent" in override
    # Not root: the agent is not an administrator of its own VM.
    assert "--autologin root" not in override


def test_netcheck_warn_keeps_the_guest_up_for_debugging(session, driver):
    """`--netcheck warn` trades the guest-side halt for being able to look."""
    payload = json.loads(user_data(session, netcheck="warn").split("\n", 1)[1])
    assert "power_state" not in payload
    assert files_in(user_data(session, netcheck="warn"))["/etc/asbx/netcheck-mode"] == "warn\n"


def test_guest_diagnostics_are_shared_back_to_the_host(session, driver):
    """A guest that powers itself off must still leave an explanation."""
    specs = [a for a in driver.build_argv() if a.startswith("virtio-fs")]
    assert any("mountTag=asbxlog" in s for s in specs)
    assert any(str(session.paths.guest_logs) in s for s in specs)

    payload = json.loads(user_data(session).split("\n", 1)[1])
    assert ["asbxlog", "/var/log/asbx", "virtiofs", "rw,nofail", "0", "0"] in payload["mounts"]


def test_netcheck_asks_where_packets_would_actually_go(session, driver):
    """wg-quick uses policy routing, so `route show default` is empty."""
    netcheck = files_in(user_data(session))["/usr/local/bin/asbx-netcheck"]
    assert "ip -4 route get 1.1.1.1" in netcheck
    assert "wg show wg0 peers" in netcheck


def test_a_mounts_guest_path_is_exactly_what_was_given(session, tmp_path):
    """`--mount HOST:GUEST` lands at GUEST inside the guest - no implicit
    mirroring of the host path, since both sides are always explicit now."""
    from agentsandbox.manager import SessionManager

    project = tmp_path / "work"
    project.mkdir()
    manager = SessionManager.create(
        allow_hosts=["example.com"],
        mounts=[Mount(host=str(project), guest="/srv/app")],
    )

    rendered = render_user_data(
        session=manager.session,
        wg_config=manager.session.paths.guest_wireguard_conf.read_text(),
        ca_cert=FAKE_CA,
        net=guest_network_facts(GatewayConfig()),
        mounts=list(manager.session.mounts),
    )
    payload = json.loads(rendered.split("\n", 1)[1])
    mount = next(m for m in payload["mounts"] if m[0] == "m0")
    assert mount[1] == "/srv/app"
    # The host side still points at the real directory.
    assert any(m.host == str(project) for m in manager.session.mounts)


def test_capability_placeholders_are_delivered_as_guest_environment(session, driver):
    """The agent reads $GITHUB_TOKEN; it never hardcodes a placeholder.

    Without this the operator pastes cap_v1_... by hand and it breaks on every
    session restart, since placeholders are minted per session.
    """
    rendered = render_user_data(
        session=session,
        wg_config=session.paths.guest_wireguard_conf.read_text(),
        ca_cert=FAKE_CA,
        net=guest_network_facts(GatewayConfig()),
        capability_env={"GITHUB_TOKEN": "cap_v1_abc", "OPENAI_API_KEY": "cap_v1_def"},
    )
    files = files_in(rendered)

    env_file = files["/run/asbx/capabilities.env"]
    assert "export GITHUB_TOKEN=cap_v1_abc" in env_file
    assert "export OPENAI_API_KEY=cap_v1_def" in env_file

    # Readable by the agent alone - `builder` runs package installs and must
    # not be able to read the placeholders.
    payload = json.loads(rendered.split("\n", 1)[1])
    entry = next(f for f in payload["write_files"] if f["path"] == "/run/asbx/capabilities.env")
    assert entry["permissions"] == "0600"
    # Root-owned at write time and chowned by the bootstrap: cloud-init runs
    # write_files before users_groups, so naming `agent` here fails the chown
    # and aborts the module, skipping every later entry.
    assert entry["owner"] == "root:root"

    # And an interactive shell picks them up.
    assert "capabilities.env" in files["/etc/profile.d/asbx-capabilities.sh"]


def test_no_capabilities_means_an_empty_env_file(session, driver):
    files = files_in(
        render_user_data(
            session=session,
            wg_config=session.paths.guest_wireguard_conf.read_text(),
            ca_cert=FAKE_CA,
            net=guest_network_facts(GatewayConfig()),
        )
    )
    assert files["/run/asbx/capabilities.env"] == ""


def test_writable_mounts_are_handed_to_the_agent(session, tmp_path):
    """The agent must be able to write a mount it was given as read-write."""
    from agentsandbox.manager import SessionManager

    project = tmp_path / "work"
    project.mkdir()
    manager = SessionManager.create(
        allow_hosts=["example.com"], mounts=[Mount(host=str(project), guest=str(project))]
    )

    payload = json.loads(
        render_user_data(
            session=manager.session,
            wg_config=manager.session.paths.guest_wireguard_conf.read_text(),
            ca_cert=FAKE_CA,
            net=guest_network_facts(GatewayConfig()),
            mounts=list(manager.session.mounts),
        ).split("\n", 1)[1]
    )
    assert ["chown", "agent:agent", str(project)] in payload["runcmd"]


def test_read_only_mounts_are_not_chowned(session, driver, tmp_path):
    docs = tmp_path / "docs"
    docs.mkdir()
    payload = json.loads(
        render_user_data(
            session=session,
            wg_config=session.paths.guest_wireguard_conf.read_text(),
            ca_cert=FAKE_CA,
            net=guest_network_facts(GatewayConfig()),
            mounts=[Mount(host=str(docs), guest="/mnt/docs", read_only=True)],
        ).split("\n", 1)[1]
    )
    assert not any(c[:2] == ["chown", "agent:agent"] and "docs" in c[-1] for c in payload["runcmd"])


def test_mounts_are_read_write_by_default(tmp_path):
    """Matches Docker/Podman's own -v: an unmarked mount is writable, :ro is
    what restricts it - there is no separate read-only-by-default share."""
    from agentsandbox.manager import SessionManager

    project = tmp_path / "work"
    project.mkdir()
    manager = SessionManager.create(
        allow_hosts=["example.com"], mounts=[Mount(host=str(project), guest=str(project))]
    )
    assert manager.session.mounts[0].read_only is False


def test_booting_without_a_ca_is_refused(session, tmp_path):
    """A guest with no CA fails every TLS request for reasons that look unrelated.

    Regression: the CA was rendered as "" when mitmproxy had not written it
    yet, cloud-init silently omitted the file, and the guest booted with an
    empty trust store — apt and curl then failed with certificate errors.
    """
    from agentsandbox.errors import SessionError
    from agentsandbox.wireguard import WireGuardIdentity

    session.paths.create()
    WireGuardIdentity.generate().write_guest_config(session.paths.guest_wireguard_conf)
    # No CA written.
    driver = VfkitDriver(session, VmConfig())
    with pytest.raises(SessionError, match="session CA missing"):
        driver.write_cloud_init()


def test_an_empty_ca_file_is_also_refused(session):
    from agentsandbox.errors import SessionError
    from agentsandbox.wireguard import WireGuardIdentity

    session.paths.create()
    WireGuardIdentity.generate().write_guest_config(session.paths.guest_wireguard_conf)
    session.paths.ca_cert.write_text("   \n")

    driver = VfkitDriver(session, VmConfig())
    with pytest.raises(SessionError, match="session CA missing"):
        driver.write_cloud_init()


def test_the_guest_link_is_not_required_for_network_online():
    """The unit installs no default route on purpose - wg0 carries everything.

    systemd-networkd-wait-online only calls a link "routable" once it has one,
    so without this it waits out its full two-minute timeout. Ubuntu orders
    cloud-init's later stages behind network-online.target, so that delay lands
    squarely before runcmd - which is what starts the bootstrap. The guest sits
    there looking dead, waiting for a route it was designed never to have.
    """
    from agentsandbox.vm.cloudinit import render_network

    unit = render_network({"address": "192.168.127.2/24", "gateway": "192.168.127.1"})
    assert "RequiredForOnline=no" in unit
    assert "[Link]" in unit
    # The reason it is safe: still no default route, only the endpoint route.
    assert "Gateway=" not in unit


def test_rendering_without_a_session_ca_is_refused():
    """A guest with no CA boots healthily and fails every https request.

    The bootstrap said FATAL and carried on, so the symptom arrived later as
    "certificate verify failed" from apt, curl and pip at once - a long way
    from the empty string that caused it. Both ends now refuse: this one so it
    cannot be rendered, and the bootstrap so it cannot be booted.
    """
    from agentsandbox.vm.cloudinit import render_user_data

    with pytest.raises(ValueError, match="session CA"):
        render_user_data(
            session=None, wg_config="", ca_cert="   ", net={"address": "1.2.3.4/24", "gateway": "1.2.3.1"}
        )


def test_ssh_starts_before_the_bootstrap(session, driver):
    """cloud-init stops at the first failing runcmd, so with ssh last a failed
    bootstrap took away the shell you need to diagnose it."""
    rendered = user_data(
        session,
        ssh_host_key="HOSTKEY",
        ssh_host_pub="ssh-ed25519 AAAA host",
        ssh_authorized_key="ssh-ed25519 AAAA client",
    )
    runcmd = json.loads(rendered.split("\n", 1)[1])["runcmd"]
    flat = [" ".join(entry) if isinstance(entry, list) else str(entry) for entry in runcmd]

    ssh_at = next(i for i, c in enumerate(flat) if "asbx-sshd-vsock" in c)
    boot_at = next(i for i, c in enumerate(flat) if "asbx-bootstrap" in c)
    assert ssh_at < boot_at


def test_no_write_files_entry_names_a_user_cloud_init_has_not_created_yet(session, driver):
    """cloud-init runs write_files before users_groups.

    An entry owned by `agent` fails its chown, and cc_write_files aborts -
    silently skipping every entry after it. That took out the sshd unit and
    the session CA, and presented as a guest with no https and no ssh rather
    than as a file that failed to write. Ownership belongs in the bootstrap,
    which runs once the accounts exist.
    """
    payload = json.loads(user_data(session).split("\n", 1)[1])
    offenders = [
        f["path"] for f in payload["write_files"] if f.get("owner", "root:root") != "root:root"
    ]
    assert not offenders


def test_cloud_init_log_is_copied_where_the_host_can_read_it(session, driver):
    """A guest that fails early powers itself off, taking its journal with it.
    cloud-init's log is the only record of what happened before runcmd."""
    payload = json.loads(user_data(session).split("\n", 1)[1])
    flat = " ".join(" ".join(c) if isinstance(c, list) else str(c) for c in payload["runcmd"])
    assert "cloud-init.log" in flat and "/var/log/asbx" in flat
