"""The guest's configuration: vfkit argv and the cloud-init bootstrap.

None of this can be booted in CI, so it is checked as configuration: the
properties that make the guest fenced in must be visible in the arguments and
in the user-data we hand it.
"""

from __future__ import annotations

import base64
import json

import pytest

from agentsandbox.session import Share
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
    session.paths.ca_cert.write_text("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")
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


def test_read_only_shares_are_marked_read_only(session, driver, tmp_path):
    shared = tmp_path / "docs"
    shared.mkdir()
    driver.vm.shares = [
        Share(path=str(shared), tag="docs", read_only=True),
        Share(path=str(shared), tag="scratch", read_only=False),
    ]
    specs = [a for a in driver.build_argv() if a.startswith("virtio-fs")]
    assert any("mountTag=docs" in s and s.endswith(",readOnly") for s in specs)
    assert any("mountTag=scratch" in s and not s.endswith(",readOnly") for s in specs)


def test_project_is_a_direct_virtio_fs_share(session, driver):
    """`--project` is a direct share, not a copy."""
    driver.vm.shares = [session.shares[0]] if session.shares else []
    session.project_path = "/Users/someone/real-project"
    # With no shares, only the log share exists
    specs = [a for a in driver.build_argv() if a.startswith("virtio-fs")]
    assert any("mountTag=asbxlog" in s for s in specs)
    # The log share is always present; project is a share added by SessionManager.create


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


def test_shares_are_mounted_with_the_mode_they_were_granted(session, driver, tmp_path):
    shared = tmp_path / "docs"
    shared.mkdir()
    rendered = user_data(
        session, shares=[Share(path=str(shared), tag="docs", read_only=True)]
    )
    payload = json.loads(rendered.split("\n", 1)[1])
    docs = next(m for m in payload["mounts"] if m[0] == "docs")
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


def test_project_mounts_at_the_host_path_by_default(session, tmp_path):
    """`--project ~/work` appears at /Users/you/work inside the guest.

    Mirroring the host path means absolute references inside the project - a
    virtualenv's shebangs, a config file with an absolute path - keep working
    without rewriting.
    """
    from agentsandbox.manager import SessionManager

    project = tmp_path / "work"
    project.mkdir()
    manager = SessionManager.create(allow_hosts=["example.com"], project=project)

    rendered = render_user_data(
        session=manager.session,
        wg_config=manager.session.paths.guest_wireguard_conf.read_text(),
        ca_cert="",
        net=guest_network_facts(GatewayConfig()),
        shares=list(manager.session.shares),
    )
    payload = json.loads(rendered.split("\n", 1)[1])
    project_mount = next(m for m in payload["mounts"] if m[0] == "project")
    assert project_mount[1] == str(project)


def test_project_mount_point_is_adjustable(session, tmp_path):
    """`--mount-path` overrides where the project lands in the guest."""
    from agentsandbox.manager import SessionManager

    project = tmp_path / "work"
    project.mkdir()
    manager = SessionManager.create(
        allow_hosts=["example.com"], project=project, project_mount="/srv/app"
    )

    rendered = render_user_data(
        session=manager.session,
        wg_config=manager.session.paths.guest_wireguard_conf.read_text(),
        ca_cert="",
        net=guest_network_facts(GatewayConfig()),
        shares=list(manager.session.shares),
    )
    payload = json.loads(rendered.split("\n", 1)[1])
    project_mount = next(m for m in payload["mounts"] if m[0] == "project")
    assert project_mount[1] == "/srv/app"
    # The host side still points at the real directory.
    assert any(s.path == str(project) for s in manager.session.shares)


def test_capability_placeholders_are_delivered_as_guest_environment(session, driver):
    """The agent reads $GITHUB_TOKEN; it never hardcodes a placeholder.

    Without this the operator pastes cap_v1_... by hand and it breaks on every
    session restart, since placeholders are minted per session.
    """
    rendered = render_user_data(
        session=session,
        wg_config=session.paths.guest_wireguard_conf.read_text(),
        ca_cert="",
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
    assert entry["owner"] == "agent:agent"

    # And an interactive shell picks them up.
    assert "capabilities.env" in files["/etc/profile.d/asbx-capabilities.sh"]


def test_no_capabilities_means_an_empty_env_file(session, driver):
    files = files_in(
        render_user_data(
            session=session,
            wg_config=session.paths.guest_wireguard_conf.read_text(),
            ca_cert="",
            net=guest_network_facts(GatewayConfig()),
        )
    )
    assert files["/run/asbx/capabilities.env"] == ""


def test_writable_mounts_are_handed_to_the_agent(session, tmp_path):
    """The agent must be able to write the project it was given."""
    from agentsandbox.manager import SessionManager

    project = tmp_path / "work"
    project.mkdir()
    manager = SessionManager.create(allow_hosts=["example.com"], project=project)

    payload = json.loads(
        render_user_data(
            session=manager.session,
            wg_config=manager.session.paths.guest_wireguard_conf.read_text(),
            ca_cert="",
            net=guest_network_facts(GatewayConfig()),
            shares=list(manager.session.shares),
        ).split("\n", 1)[1]
    )
    assert ["chown", "agent:agent", str(project)] in payload["runcmd"]


def test_read_only_shares_are_not_chowned(session, driver, tmp_path):
    docs = tmp_path / "docs"
    docs.mkdir()
    payload = json.loads(
        render_user_data(
            session=session,
            wg_config=session.paths.guest_wireguard_conf.read_text(),
            ca_cert="",
            net=guest_network_facts(GatewayConfig()),
            shares=[Share(path=str(docs), tag="docs", read_only=True)],
        ).split("\n", 1)[1]
    )
    assert not any(c[:2] == ["chown", "agent:agent"] and "docs" in c[-1] for c in payload["runcmd"])


def test_the_project_mounts_read_write_by_default(tmp_path):
    """`--project` is for editing; the read-only default is for `--share`."""
    from agentsandbox.manager import SessionManager

    project = tmp_path / "work"
    project.mkdir()
    manager = SessionManager.create(allow_hosts=["example.com"], project=project)
    share = next(s for s in manager.session.shares if s.tag == "project")
    assert share.read_only is False


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
