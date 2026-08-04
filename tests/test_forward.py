"""Port forwarding.

Note on coverage: this suite exercises the listener and the port syntax, not a
full proxied connection. Claude's sandbox denies *outbound* loopback
connections, so a test that dials the forwarder it just started cannot run
here; binding and the pure functions can.
"""

from __future__ import annotations

import argparse
import asyncio

from agentsandbox.cli import _parse_forward
from agentsandbox.forward import PortForwarder, TcpDialer, UnixDialer, is_loopback


def test_only_loopback_peers_are_accepted():
    assert is_loopback(("127.0.0.1", 5000))
    assert is_loopback(("::1", 5000))
    assert not is_loopback(("192.168.1.20", 5000))
    assert not is_loopback(("0.0.0.0", 5000))
    assert not is_loopback(None)


def test_forwarder_binds_loopback_only():
    """Binding 0.0.0.0 would put the guest's server on the local network."""

    async def run():
        forwarder = PortForwarder(TcpDialer("127.0.0.1", 3000), guest_port=3000)
        url = await forwarder.start()
        try:
            assert url.startswith("http://127.0.0.1:")
            assert forwarder.port != 0
            assert forwarder._server.sockets[0].getsockname()[0] == "127.0.0.1"
        finally:
            await forwarder.stop()

    asyncio.run(run())


def test_url_has_no_secret_path():
    """Plain URLs: paste-able, and the loopback bind is the control."""
    forwarder = PortForwarder(TcpDialer("127.0.0.1", 3000), guest_port=3000, port=8080)
    assert forwarder.url == "http://127.0.0.1:8080/"


def test_dialers_describe_themselves(tmp_path):
    assert UnixDialer(tmp_path / "p.sock").describe().startswith("unix:")
    assert TcpDialer("127.0.0.1", 3000).describe() == "tcp:127.0.0.1:3000"


def test_vsock_port_convention_matches_the_guest_script():
    from agentsandbox.vm import app_port_for, vsock_port_for

    assert vsock_port_for(3000) == 43000
    assert app_port_for(43000) == 3000


# -- CLI port syntax ---------------------------------------------------------


def test_forward_port_syntax():
    """docker-style: PORT, or HOST:GUEST with the host side first."""
    assert _parse_forward("3000") == (3000, 3000)
    assert _parse_forward("8080:3000") == (8080, 3000)


def test_forward_port_syntax_rejects_nonsense():
    for bad in ("", "abc", "3000:", "0", "70000", "8080:99999"):
        try:
            _parse_forward(bad)
        except argparse.ArgumentTypeError:
            continue
        raise AssertionError(f"{bad!r} should have been rejected")
