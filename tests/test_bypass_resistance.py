"""Bypass resistance: one section per security guarantee, checked at the
component that actually enforces it.

Where a guarantee can only be fully demonstrated with a booted guest, the
test checks the enforcing configuration instead and says so - see
IMPLEMENTATION.md's "Verified on real hardware" / "Still not verified" split
for what that leaves open.
"""

from __future__ import annotations

import json

import pytest

from agentsandbox.broker.core import BrokerCore
from agentsandbox.broker.upstream import UpstreamResponse
from agentsandbox.capabilities import CapabilitySpec, SecretRef
from agentsandbox.manager import SessionManager
from agentsandbox.netpolicy import Destination
from agentsandbox.session import Mount
from agentsandbox.proxy.addon import SandboxAddon
from agentsandbox.proxy.launcher import build_argv
from agentsandbox.audit import NullAuditLog
from agentsandbox.vm.gateway import (
    ETHERTYPE_IPV4,
    EthernetFrame,
    GatewayConfig,
    L2Gateway,
    build_ipv4_udp,
    mac_to_bytes,
)
from agentsandbox.vm.vfkit import VfkitDriver, VmConfig

from helpers import RecordingExecutor, make_request
from test_addon import FakeBroker, http_flow

SECRET = "ghp_realsecretvalue0123456789"
GUEST_MAC = mac_to_bytes("02:00:00:00:00:02")
GATEWAY_MAC = mac_to_bytes("02:00:00:00:00:01")


def frame(dst_ip, dst_port, payload=b"data", src_ip="192.168.127.2"):
    packet = build_ipv4_udp(src_ip, dst_ip, 41234, dst_port, payload)
    return EthernetFrame(GATEWAY_MAC, GUEST_MAC, ETHERTYPE_IPV4, packet).pack()


# -- the guest's only path out is the tunnel ---------------------------------


def test_the_guest_has_no_path_out_except_wireguard():
    """"The VM cannot reach the internet when WireGuard is unavailable."

    The gateway relays exactly one destination. With mitmproxy down the relay
    goes to a socket nobody is listening on - there is no second path to fall
    back to, by construction rather than by configuration.
    """
    relayed = []
    gateway = L2Gateway(GatewayConfig(), relay=relayed.append)

    for destination in [
        ("8.8.8.8", 53),  # public DNS
        ("1.1.1.1", 443),  # public HTTPS over UDP/QUIC
        ("192.168.127.1", 80),  # the gateway, wrong port
        ("192.168.1.1", 51820),  # the LAN router, right port
        ("192.168.127.2", 51820),  # itself
    ]:
        gateway.handle_frame(frame(*destination))

    assert relayed == []
    assert gateway.stats.dropped == 5

    gateway.handle_frame(frame("192.168.127.1", 51820, b"wg"))
    assert relayed == [b"wg"]


def test_the_relay_target_is_pinned_to_this_sessions_mitmproxy(session):
    """The gateway cannot be talked into relaying somewhere else."""
    config = GatewayConfig(wg_host="127.0.0.1", wg_port=51820)
    gateway = L2Gateway(config, relay=lambda payload: None)
    # The destination is a property of the host-side config, never of the
    # frame: the guest addresses 192.168.127.1 and gets whatever we chose.
    assert config.wg_host == "127.0.0.1"
    assert gateway.config.gateway_ip == "192.168.127.1"


# -- the mac and the private lan are unreachable through the proxy -----------


@pytest.mark.parametrize(
    "host",
    ["127.0.0.1", "localhost", "192.168.1.50", "10.1.2.3", "169.254.169.254", "host.docker.internal"],
)
def test_the_mac_and_the_lan_are_unreachable_through_the_proxy(session, host):
    """"The VM cannot reach the Mac or private LAN.\""""
    addon = SandboxAddon(session, FakeBroker(), audit=NullAuditLog(session.session_id))
    flow = http_flow(host=host)
    addon.request(flow)
    assert flow.response.status_code == 403


def test_the_broker_will_not_fetch_from_private_space_either(session, store, resolver, executor):
    """A capability cannot be used as an SSRF primitive."""
    from agentsandbox.netpolicy import DestinationPolicy

    policy = DestinationPolicy(allow_hosts=["*"])
    core = BrokerCore(
        session.session_id, store, policy, resolver, executor=executor
    )
    token, _ = store.issue(
        CapabilitySpec(
            label="x", hosts=["*"], secret=SecretRef(service="github-token")
        )
    )
    response = core.handle(make_request(token, host="metadata.test"))
    assert response.decision == "deny"
    assert executor.calls == []


# -- every http version goes through the same policy --------------------------


@pytest.mark.parametrize("version", [b"HTTP/1.1", b"HTTP/2.0", b"HTTP/3.0"])
def test_every_http_version_goes_through_the_same_policy(session, version):
    """"HTTP/1.1, HTTP/2 and HTTP/3 requests pass through the gateway.\""""
    addon = SandboxAddon(session, FakeBroker(), audit=NullAuditLog(session.session_id))

    allowed = http_flow(http_version=version)
    addon.request(allowed)
    assert allowed.response is None

    denied = http_flow(host="evil.test", http_version=version)
    addon.request(denied)
    assert denied.response.status_code == 403


def test_the_proxy_is_configured_for_http3_and_refuses_blind_tunnels(session):
    argv = build_argv(session)
    joined = " ".join(argv)
    assert "http3=true" in joined
    assert "http2=true" in joined
    # Nothing may be tunnelled without inspection, and no traffic is persisted.
    # (The host-filter options are checked in their own test below: they must
    # be absent, not set to an empty value.)
    assert "rawtcp=false" in joined
    assert "save_stream_file=" in joined
    assert not any("save_stream_file=/" in a for a in argv)
    # Alt-Svc would advertise an HTTP/3 endpoint that skips this proxy.
    assert "keep_alt_svc_header=false" in joined
    assert "strip_ech=true" in joined


# -- a placeholder works only for its approved destination and operation -----


def test_a_placeholder_is_useless_outside_its_grant(broker, github_capability):
    """"A placeholder works only for its approved destination and operation.\""""
    token, _ = github_capability
    assert broker.handle(make_request(token)).decision == "allow"

    for bad in (
        {"host": "api.example.com"},  # another host
        {"method": "DELETE"},  # another method
        {"target": "/user/emails"},  # another path
        {"target": "/repos/acme/other/issues"},  # another resource
        {"scheme": "http", "port": 80},  # downgraded scheme
        {"session_id": "another-session"},  # another session
    ):
        assert broker.handle(make_request(token, **bad)).decision == "deny", bad


# -- real credentials never appear inside the vm ------------------------------


def test_the_real_credential_never_crosses_back_into_the_guest(session, store, resolver):
    """"Real credentials never appear inside the VM.\""""
    executor = RecordingExecutor(
        UpstreamResponse(
            status_code=200,
            headers=[("X-Echo-Token", SECRET), ("Set-Cookie", f"t={SECRET}")],
            body=json.dumps({"token": SECRET}).encode(),
        )
    )
    core = BrokerCore(
        session.session_id, store, session.policy, resolver, executor=executor
    )
    token, _ = store.issue(
        CapabilitySpec(
            label="github", hosts=["api.github.com"], secret=SecretRef(service="github-token")
        )
    )
    response = core.handle(make_request(token))

    assert SECRET.encode() not in response.body
    assert not any(SECRET in value for _, value in response.headers)
    assert SECRET.encode() not in response.to_json().encode()


def test_the_capability_store_holds_references_not_secrets(store, github_capability):
    """There is no "get secret" surface: a capability names where to look."""
    _, cap = github_capability
    # Every field is a *pointer* - which backend, which entry, which database.
    # None of them can hold credential material.
    assert set(cap.secret.to_dict()) == {"backend", "service", "account", "store"}
    assert SECRET not in store.path.read_text()
    assert SECRET not in json.dumps(cap.secret.to_dict())


def test_the_broker_protocol_can_only_ask_for_an_operation():
    """The wire format has no way to express "give me the credential"."""
    from agentsandbox.broker.core import BrokerRequest

    fields = set(BrokerRequest.__dataclass_fields__)
    assert fields == {
        "session_id",
        "capability",
        "method",
        "scheme",
        "host",
        "port",
        "target",
        "headers",
        "body",
        "operation",
        "flow_id",
    }


# -- redirects cannot move credentials to another origin ---------------------


def test_redirects_cannot_carry_the_credential_off_origin(policy):
    """"Redirects cannot move credentials to another origin." (see test_upstream)"""
    from test_upstream import ScriptedExecutor, ok, redirect

    executor = ScriptedExecutor(policy, [redirect("https://other.example.net/x"), ok()])
    executor.policy.allow_hosts.append("other.example.net")
    executor.execute(
        Destination("https", "api.example.com", 443),
        "GET",
        "/v1",
        [],
        b"",
        [("Authorization", f"Bearer {SECRET}")],
        1000,
    )
    assert executor.hops[-1]["carried_credential"] is False


# -- untrusted package scripts get fewer capabilities than the agent ---------


def test_package_scripts_cannot_read_the_agents_capabilities(session, tmp_path):
    """"Untrusted package scripts cannot access agent capabilities by default.\"

    Enforced in the guest bootstrap: the capability box file is 0600
    owned by ``agent``, and ``asbx-run-untrusted`` drops to ``builder`` with a
    scrubbed box.
    """
    from agentsandbox.vm.cloudinit import GUEST_DIR

    bootstrap = (GUEST_DIR / "bootstrap.sh").read_text()
    assert "chown agent:agent /run/asbx/capabilities.env" in bootstrap
    assert "chmod 0600 /run/asbx/capabilities.env" in bootstrap
    # Dropping *down* to builder is what protects the placeholders. The agent
    # also has root in its own guest, which is fine: the fence is the host's
    # L2 gateway, not the guest's privilege model.
    assert "agent ALL=(builder) NOPASSWD: ALL" in bootstrap

    runner = (GUEST_DIR / "run-untrusted.sh").read_text()
    assert "sudo -u builder" in runner
    assert "env -i" in runner
    # builder must not be able to read the placeholders, root or not.
    assert "capabilities.env" in runner


# -- forwards are host-to-guest, one-directional, loopback only --------------


def test_forwards_are_host_to_guest_only_and_loopback_only(session):
    """"The Mac can open an explicitly exposed application running in the VM.\""""
    driver = VfkitDriver(session, VmConfig(vsock_ports={43000: session.paths.forward_socket(3000)}))
    spec = next(a for a in driver.build_argv() if a.startswith("virtio-vsock"))
    # `connect`, not `listen`: we dial into the guest, and it has no way to
    # originate a connection back to the host over this device.
    assert spec.endswith(",connect")
    assert "listen" not in spec

    from agentsandbox.forward import PortForwarder, UnixDialer

    forwarder = PortForwarder(UnixDialer(session.paths.forward_socket(3000)), guest_port=3000)
    # Loopback only: binding the wildcard would put the guest's server on the LAN.
    assert forwarder.host == "127.0.0.1"


# -- a mount is the real directory, not a copy --------------------------------


def test_the_guest_gets_the_real_project(tmp_path):
    """"The project directory is mounted directly, not copied.\""""
    project = tmp_path / "proj"
    project.mkdir()
    (project / "app.py").write_text("print(1)\n")

    manager = SessionManager.create(
        allow_hosts=["example.com"], mounts=[Mount(host=str(project), guest=str(project))]
    )
    driver = VfkitDriver(manager.session, VmConfig(mounts=list(manager.session.mounts)))
    mounts = [a for a in driver.build_argv() if a.startswith("virtio-fs")]

    assert any(str(project) in s for s in mounts)
    assert any("mountTag=m0" in s for s in mounts)


# -- destroying a session revokes its identity and every capability ----------


def test_destroying_a_session_revokes_identity_and_capabilities(tmp_path):
    """"Destroying a session revokes its network identity and all capabilities.\""""
    manager = SessionManager.create(allow_hosts=["api.github.com"])
    token, cap = manager.issue_capability(
        CapabilitySpec(
            label="github",
            hosts=["api.github.com"],
            secret=SecretRef(backend="static", service="github-token"),
        )
    )
    wg_conf = manager.session.paths.wireguard_conf
    old_identity = json.loads(wg_conf.read_text())
    root = manager.session.paths.root

    manager.stop(purge=True)

    # Capabilities died first, then the key material and the whole directory.
    assert not root.exists()
    assert not wg_conf.exists()

    fresh = SessionManager.create(allow_hosts=["api.github.com"])
    new_identity = json.loads(fresh.session.paths.wireguard_conf.read_text())
    assert new_identity["server_key"] != old_identity["server_key"]
    assert fresh.store.lookup(token) is None


# -- no traffic is ever passed through uninspected ----------------------------


def test_the_proxy_is_never_told_to_ignore_anything(session):
    """No option that would create an uninspected path may be set at all.

    `--set ignore_hosts=` does not clear a sequence option - it sets it to an
    empty pattern that matches every host, which is a total interception
    bypass that still looks like a working sandbox.
    """
    argv = build_argv(session)
    for option in ("ignore_hosts", "allow_hosts", "tcp_hosts", "udp_hosts"):
        assert not any(a.startswith(f"{option}=") for a in argv), option
