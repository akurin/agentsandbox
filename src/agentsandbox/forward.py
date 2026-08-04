"""Port forwarding: reach a port inside the guest from the Mac.

    Mac client  -> 127.0.0.1:<port>    (this module)
                -> unix socket         (vfkit's vsock bridge)
                -> guest vsock:<port>  (guest-side forwarder unit)
                -> 127.0.0.1:<app>     (whatever is listening in the guest)

The direction is the whole security argument.  We *connect into* the guest over
vsock; the guest has no listening socket on the host side of that bridge, so
forwarding a port does not give the VM a way to reach Mac services.  Nothing
here ever binds anything but the loopback interface.

The data path is a plain byte pipe with no protocol parsing, so anything TCP
forwards - a dev server, a database, a websocket - not only HTTP.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from .audit import AuditLog, NullAuditLog

_BUFFER = 64 * 1024


class Dialer(Protocol):
    """Opens the far end of a forwarded connection."""

    async def open(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]: ...

    def describe(self) -> str: ...


@dataclass
class UnixDialer:
    """Production path: the unix socket vfkit bridges to a guest vsock port."""

    path: Path

    async def open(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        return await asyncio.open_unix_connection(str(self.path))

    def describe(self) -> str:
        return f"unix:{self.path}"


@dataclass
class TcpDialer:
    """Development path: forward to a plain TCP endpoint."""

    host: str
    port: int

    async def open(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        return await asyncio.open_connection(self.host, self.port)

    def describe(self) -> str:
        return f"tcp:{self.host}:{self.port}"



def is_loopback(peer: tuple | None) -> bool:
    if not peer:
        return False
    host = str(peer[0])
    return host in ("127.0.0.1", "::1", "::ffff:127.0.0.1")


@dataclass
class PortForwarder:
    """One guest port, exposed on loopback."""

    dialer: Dialer
    guest_port: int = 0
    host: str = "127.0.0.1"
    port: int = 0
    max_connections: int = 32
    audit: AuditLog = field(default_factory=NullAuditLog)
    _server: asyncio.AbstractServer | None = None
    _connections: int = 0

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/"

    async def start(self) -> str:
        self._server = await asyncio.start_server(
            self._handle, self.host, self.port, backlog=16
        )
        # Loopback only, always: binding 0.0.0.0 would put the agent's app on
        # the local network.
        sock = self._server.sockets[0]
        self.port = sock.getsockname()[1]
        self.audit.emit(
            "forward.started",
            guest_port=self.guest_port,
            listen=f"{self.host}:{self.port}",
            upstream=self.dialer.describe(),
        )
        return self.url

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            self.audit.emit("forward.stopped", guest_port=self.guest_port)

    async def serve_forever(self) -> None:
        if self._server is None:
            await self.start()
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    # -- connection handling -------------------------------------------------

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        if not is_loopback(peer):
            self.audit.emit("forward.rejected", reason="not_loopback", peer=str(peer))
            writer.close()
            return
        if self._connections >= self.max_connections:
            self.audit.emit("forward.rejected", reason="too_many_connections")
            await _refuse(writer, 503, "too many connections")
            return

        self._connections += 1
        try:
            try:
                up_reader, up_writer = await self.dialer.open()
            except OSError as exc:
                self.audit.emit(
                    "forward.upstream_failed",
                    guest_port=self.guest_port,
                    error=exc.strerror or str(exc),
                )
                await _refuse(writer, 502, "nothing is listening on that guest port")
                return

            await asyncio.gather(
                _pump(reader, up_writer),
                _pump(up_reader, writer),
                return_exceptions=True,
            )
        finally:
            self._connections -= 1
            writer.close()



async def _pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            chunk = await reader.read(_BUFFER)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        try:
            writer.close()
        except OSError:
            pass


async def _refuse(writer: asyncio.StreamWriter, status: int, message: str) -> None:
    body = message.encode()
    writer.write(
        b"HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
        % (status, message.encode(), len(body), body)
    )
    try:
        await writer.drain()
    except ConnectionError:
        pass
    writer.close()
