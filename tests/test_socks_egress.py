"""The selected SOCKS endpoint is the only destination the transport dials."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import socketserver
import struct
import threading
from types import SimpleNamespace

import pytest
from mitmproxy.net.dns import response_codes
from mitmproxy.test import tflow
from mitmproxy import dns

from agentsandbox.audit import NullAuditLog
from agentsandbox.box import Box
from agentsandbox.broker.upstream import UpstreamExecutor
from agentsandbox.cli import build_parser
from agentsandbox.errors import PolicyDenied
from agentsandbox.netpolicy import Destination, DestinationPolicy
from agentsandbox.proxy.addon import SandboxAddon
from agentsandbox.socks import SocksEndpoint, install_mitm_transport
from agentsandbox.session import Session


class FakeSocks(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        header = _read(sock, 2)
        methods = _read(sock, header[1])
        method = 2 if 2 in methods else 0
        sock.sendall(bytes([5, method]))
        if method == 2:
            version, length = _read(sock, 2)
            user = _read(sock, length)
            password = _read(sock, _read(sock, 1)[0])
            self.server.auth = (version, user, password)
            sock.sendall(b"\x01\x00")
        version, command, reserved, kind = _read(sock, 4)
        assert (version, command, reserved, kind) == (5, 1, 0, 1)
        dest = _read(sock, 4)
        port = struct.unpack("!H", _read(sock, 2))[0]
        self.server.destinations.append((str(ipaddress.ip_address(dest)), port))
        sock.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        while data := sock.recv(4096):
            sock.sendall(data)


def _read(sock, size):
    data = b""
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise EOFError
        data += part
    return data


@pytest.fixture
def proxy():
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), FakeSocks)
    server.daemon_threads = True
    server.destinations = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_sync_socks_connect_with_authentication(proxy):
    endpoint = SocksEndpoint("127.0.0.1", proxy.server_address[1], "agent", "secret")
    with endpoint.connect("93.184.216.34", 443) as sock:
        sock.sendall(b"test")
        assert _read(sock, 4) == b"test"
    assert proxy.auth == (1, b"agent", b"secret")
    assert proxy.destinations == [("93.184.216.34", 443)]


def test_proxy_hostname_resolves_on_host_and_tunnels_destination(proxy, monkeypatch):
    original_getaddrinfo = socket.getaddrinfo
    looked_up = []

    def getaddrinfo(host, port, *args, **kwargs):
        looked_up.append(host)
        if host == "proxy.example":
            host = "127.0.0.1"
        return original_getaddrinfo(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    endpoint = SocksEndpoint.parse(
        f"socks5://agent:secret@proxy.example:{proxy.server_address[1]}"
    )
    with endpoint.connect("93.184.216.34", 443):
        pass
    assert looked_up == ["proxy.example"]
    assert proxy.destinations == [("93.184.216.34", 443)]
    assert "secret" not in endpoint.redacted()


def test_mitm_transport_dials_the_proxy_even_for_early_connections(proxy, monkeypatch):
    from mitmproxy.proxy import server

    endpoint = SocksEndpoint("127.0.0.1", proxy.server_address[1])
    monkeypatch.setattr(server, "asyncio", asyncio)
    policy = DestinationPolicy(allow_hosts=["*"], socks_egress=endpoint)
    install_mitm_transport(endpoint, policy)

    async def transfer():
        reader, writer = await server.asyncio.open_connection(
            "93.184.216.34", 443, local_addr=None
        )
        writer.write(b"hello")
        await writer.drain()
        assert await reader.readexactly(5) == b"hello"
        writer.close()
        await writer.wait_closed()

    asyncio.run(transfer())
    assert proxy.destinations == [("93.184.216.34", 443)]


def test_mitm_transport_rechecks_dns_and_refuses_private_answers(proxy, monkeypatch):
    from mitmproxy.proxy import server

    endpoint = SocksEndpoint("127.0.0.1", proxy.server_address[1])
    policy = DestinationPolicy(allow_hosts=["*"], socks_egress=endpoint)
    monkeypatch.setattr(SocksEndpoint, "resolve", lambda self, host: [ipaddress.ip_address("127.0.0.1")])
    monkeypatch.setattr(server, "asyncio", asyncio)
    install_mitm_transport(endpoint, policy)

    async def blocked():
        with pytest.raises(PolicyDenied):
            await server.asyncio.open_connection("example.com", 443)

    asyncio.run(blocked())
    assert proxy.destinations == []


def test_mitm_transport_refuses_an_unknown_dial_path(monkeypatch):
    from mitmproxy.proxy import server
    from agentsandbox import socks

    monkeypatch.setattr(server, "asyncio", asyncio)
    monkeypatch.setattr(socks.inspect, "getsource", lambda function: "changed transport")
    endpoint = SocksEndpoint("127.0.0.1", 1080)
    policy = DestinationPolicy(socks_egress=endpoint)
    with pytest.raises(RuntimeError, match="dial path changed"):
        install_mitm_transport(endpoint, policy)
    assert server.asyncio is asyncio


def test_broker_connects_to_pinned_address_through_socks(proxy, monkeypatch):
    endpoint = SocksEndpoint("127.0.0.1", proxy.server_address[1])
    monkeypatch.setattr(SocksEndpoint, "resolve", lambda self, host: [ipaddress.ip_address("93.184.216.34")])
    policy = DestinationPolicy(allow_hosts=["example.com"], socks_egress=endpoint)
    conn = UpstreamExecutor(policy)._connect(Destination("https", "example.com", 443))
    with conn._create_connection(("example.com", 443), timeout=30):
        pass
    assert proxy.destinations == [("93.184.216.34", 443)]


def test_browser_transport_pins_the_address_through_socks(proxy):
    from curl_cffi import CurlOpt
    from curl_cffi.requests import AsyncSession

    endpoint = SocksEndpoint("127.0.0.1", proxy.server_address[1])

    async def request():
        async with AsyncSession(
            curl_options={CurlOpt.RESOLVE: ["example.com:80:93.184.216.34"]}
        ) as session:
            with pytest.raises(Exception):
                await session.request(
                    "GET", "http://example.com:80/", proxy=endpoint.url(), timeout=2
                )

    asyncio.run(request())
    assert proxy.destinations == [("93.184.216.34", 80)]


def test_proxy_failure_does_not_dial_the_destination(monkeypatch):
    endpoint = SocksEndpoint("127.0.0.1", 1)
    monkeypatch.setattr(SocksEndpoint, "resolve", lambda self, host: [ipaddress.ip_address("93.184.216.34")])
    policy = DestinationPolicy(allow_hosts=["example.com"], socks_egress=endpoint)
    conn = UpstreamExecutor(policy)._connect(Destination("https", "example.com", 443))
    with pytest.raises(OSError):
        conn._create_connection(("example.com", 443), timeout=30)


def test_box_persists_egress_without_showing_password():
    endpoint = SocksEndpoint.parse("socks5://agent:secret@127.0.0.1:1080")
    box = Box("neo", socks_egress=endpoint)
    box.save()
    loaded = Box.load("neo")
    assert loaded.socks_egress == endpoint
    assert "secret" not in str(loaded.public_view())
    assert "secret" not in loaded.socks_egress.redacted()


def test_cli_exposes_optional_egress_for_create_and_set():
    parser = build_parser()
    created = parser.parse_args([
        "box", "create", "neo", "--socks-egress", "socks5://127.0.0.1:1080"
    ])
    assert created.socks_egress == SocksEndpoint("127.0.0.1", 1080)
    disabled = parser.parse_args(["box", "set", "neo", "--no-socks-egress"])
    assert disabled.no_socks_egress

    hostname = parser.parse_args([
        "box", "set", "--socks-egress", "socks5://agent:secret@proxy.example:8001", "neo"
    ])
    assert hostname.socks_egress.host == "proxy.example"


def test_secret_refresh_keeps_the_running_sessions_egress(monkeypatch):
    from agentsandbox import cli
    from agentsandbox.broker import server

    endpoint = SocksEndpoint("127.0.0.1", 1080)
    Box("neo", profile="example").save()  # box config changed since this run started
    session = Session("current", box_name="neo", policy=DestinationPolicy(socks_egress=endpoint))
    seen = []
    monkeypatch.setattr(cli, "_resolve_session", lambda target: session)
    monkeypatch.setattr(cli, "_warm_secrets", lambda profile, egress: (seen.append(egress), None))
    monkeypatch.setattr(cli, "read_token", lambda path: "token")
    monkeypatch.setattr(server, "send_command", lambda *args: {"ok": True})
    assert cli.cmd_secret_refresh(SimpleNamespace(box="neo")) == 0
    assert seen == [endpoint]


def test_egress_dns_uses_the_proxy_resolver(monkeypatch):
    from agentsandbox import netpolicy

    endpoint = SocksEndpoint("127.0.0.1", 1080)
    monkeypatch.setattr(netpolicy, "resolve_host", lambda host: pytest.fail("direct DNS used"))
    monkeypatch.setattr(SocksEndpoint, "resolve", lambda self, host: [ipaddress.ip_address("93.184.216.34")])
    policy = DestinationPolicy(allow_hosts=["example.com"], socks_egress=endpoint)
    policy.check(Destination("https", "example.com", 443))


def test_socks_dns_reuses_guest_answer_for_connection_checks(monkeypatch):
    endpoint = SocksEndpoint("127.0.0.1", 1080)
    request = tflow.tdnsflow().request
    request.questions[0].name = "example.com"
    answer = request.succeed([
        dns.ResourceRecord.A("example.com", ipaddress.ip_address("93.184.216.34"), ttl=30)
    ])
    endpoint._remember_dns_answer(request.question, answer)
    monkeypatch.setattr(SocksEndpoint, "dns_query", lambda self, wire: pytest.fail("duplicate DNS lookup"))

    policy = DestinationPolicy(allow_hosts=["example.com"], socks_egress=endpoint)
    assert policy.resolve_and_validate("example.com") == [ipaddress.ip_address("93.184.216.34")]
    assert policy.resolve_and_validate("example.com") == [ipaddress.ip_address("93.184.216.34")]


def test_socks_dns_cache_expires_at_answer_ttl(monkeypatch):
    from agentsandbox import socks

    endpoint = SocksEndpoint("127.0.0.1", 1080)
    request = tflow.tdnsflow().request
    request.questions[0].name = "example.com"
    answer = request.succeed([
        dns.ResourceRecord.A("example.com", ipaddress.ip_address("93.184.216.34"), ttl=1)
    ])
    now = [100.0]
    monkeypatch.setattr(socks.time, "monotonic", lambda: now[0])
    endpoint._remember_dns_answer(request.question, answer)
    assert endpoint._cached_dns_addresses("example.com", 1)
    now[0] += 1
    assert endpoint._cached_dns_addresses("example.com", 1) == []


def test_socks_dns_response_cache_restores_query_id_and_limits_ttl(monkeypatch):
    from agentsandbox import socks

    endpoint = SocksEndpoint("127.0.0.1", 1080)
    request = tflow.tdnsflow().request
    request.questions[0].name = "example.com"
    answer = request.succeed([
        dns.ResourceRecord.A("example.com", ipaddress.ip_address("93.184.216.34"), ttl=30)
    ])
    wire = b"\x00\x00" + request.packed[2:]
    answer.id = 0
    now = [100.0]
    monkeypatch.setattr(socks.time, "monotonic", lambda: now[0])
    endpoint._remember_dns_response(wire, answer.packed, answer)
    monkeypatch.setattr(SocksEndpoint, "connect", lambda *args, **kwargs: pytest.fail("DoH reopened"))

    now[0] += 10
    cached = endpoint.dns_query(b"\x04\xd2" + wire[2:])
    assert cached.id == 1234
    assert cached.answers[0].ttl == 20
    now[0] += 20
    assert endpoint._cached_dns_response(wire, 1234) is None


def test_guest_dns_is_answered_through_socks_and_bad_queries_fail_closed(session, monkeypatch):
    endpoint = SocksEndpoint("127.0.0.1", 1080)
    session.policy.socks_egress = endpoint
    addon = SandboxAddon(session, object(), audit=NullAuditLog())
    calls = []

    def answer(self, wire):
        calls.append(wire)
        return valid.request.succeed([])

    monkeypatch.setattr(SocksEndpoint, "dns_query", answer)
    valid = tflow.tdnsflow()
    valid.request.questions[0].name = "example.com"
    asyncio.run(addon.dns_request(valid))
    assert valid.response is not None and len(calls) == 1

    malformed = tflow.tdnsflow()
    malformed.request.questions.clear()
    asyncio.run(addon.dns_request(malformed))
    assert malformed.response.response_code == response_codes.REFUSED
    assert len(calls) == 1
