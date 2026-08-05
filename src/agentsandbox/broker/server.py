"""Transport for the broker.

The broker is a *separate process* from mitmproxy, so a compromised addon (or a
compromised mitmproxy dependency) still cannot read a credential - it can only
ask for an operation the capability already permits.

The channel is a unix stream socket in the session's 0700 run directory,
carrying length-prefixed JSON, with a per-session bearer token as a second
factor.  It is never bound to a TCP port: nothing routable can reach it, which
also means the guest cannot reach it even if it escapes the tunnel policy.
"""

from __future__ import annotations

import json
import os
import secrets
import socket
import socketserver
import struct
import threading
from pathlib import Path
from typing import Callable

from ..audit import AuditLog, NullAuditLog
from ..config import write_private_file
from ..errors import BrokerError
from .core import BrokerCore, BrokerRequest, BrokerResponse, denial

MAX_FRAME = 32 * 1024 * 1024
_LEN = struct.Struct("!I")


def _send_frame(sock: socket.socket, payload: bytes) -> None:
    if len(payload) > MAX_FRAME:
        raise BrokerError("frame too large")
    sock.sendall(_LEN.pack(len(payload)) + payload)


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    chunks = []
    remaining = count
    while remaining:
        chunk = sock.recv(min(remaining, 65536))
        if not chunk:
            raise BrokerError("connection closed mid-frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_frame(sock: socket.socket) -> bytes:
    (length,) = _LEN.unpack(_recv_exact(sock, _LEN.size))
    if length > MAX_FRAME:
        raise BrokerError("frame too large")
    return _recv_exact(sock, length)


def issue_token(path: Path) -> str:
    """Create (or replace) the shared token the addon presents to the broker."""
    token = secrets.token_urlsafe(32)
    write_private_file(path, token)
    return token


def read_token(path: Path) -> str:
    if not path.exists():
        raise BrokerError(f"broker token missing at {path}")
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        raise BrokerError(f"broker token {path} is group/world readable ({mode:o})")
    return path.read_text().strip()


class _Handler(socketserver.BaseRequestHandler):
    server: "BrokerServer"

    def handle(self) -> None:  # noqa: D102
        sock: socket.socket = self.request
        try:
            while True:
                try:
                    frame = _recv_frame(sock)
                except BrokerError:
                    return
                try:
                    message = json.loads(frame)
                except json.JSONDecodeError:
                    _send_frame(sock, denial("bad_request", "malformed frame").to_json().encode())
                    continue

                if not secrets.compare_digest(str(message.get("token", "")), self.server.token):
                    self.server.audit.emit("broker.auth_failed", peer=str(self.client_address))
                    _send_frame(
                        sock,
                        denial("unauthenticated", "broker token rejected", status=401)
                        .to_json()
                        .encode(),
                    )
                    return

                # Control messages: the operator asking the broker to do
                # something, rather than the guest asking for an operation.
                if command := message.get("command"):
                    _send_frame(sock, self.server.handle_command(command).encode())
                    continue

                try:
                    request = BrokerRequest.from_dict(message["request"])
                except (KeyError, TypeError, ValueError):
                    _send_frame(
                        sock, denial("bad_request", "malformed request").to_json().encode()
                    )
                    continue

                response = self.server.core.handle(request)
                _send_frame(sock, response.to_json().encode())
        except (ConnectionError, OSError):
            return


class BrokerServer(socketserver.ThreadingUnixStreamServer):
    """Threaded unix-socket server wrapping a :class:`BrokerCore`."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        core: BrokerCore,
        socket_path: Path,
        token: str,
        audit: AuditLog | None = None,
    ) -> None:
        self.core = core
        self.token = token
        self.audit = audit or NullAuditLog(core.session_id)
        self.socket_path = socket_path
        #: Extra operator commands, registered by whoever owns the thing they
        #: act on. The broker runs inside the supervisor, so this socket is the
        #: only authenticated way for a CLI process to reach the running
        #: session - which is what lets mitmweb be attached without a restart.
        self.commands: dict[str, "Callable[[], dict]"] = {}
        socket_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(socket_path.parent, 0o700)
        if socket_path.exists():
            socket_path.unlink()
        old_umask = os.umask(0o177)  # socket lands as 0600
        try:
            super().__init__(str(socket_path), _Handler)
        finally:
            os.umask(old_umask)

    def handle_command(self, command: str) -> str:
        """Operator commands, arriving over the same authenticated socket.

        Only ``refresh-secrets`` for now: it drops the broker's cached
        credentials so the next brokered request re-reads them. The operator
        runs `asbx secret refresh` while present, which unlocks the store
        again; this is what lets a rotated credential land without restarting
        a box that has been running for days.
        """
        if handler := self.commands.get(command):
            try:
                return json.dumps(handler())
            except Exception as exc:  # noqa: BLE001 - reported, never fatal
                self.audit.emit("command.failed", command=command, error=str(exc))
                return json.dumps({"ok": False, "error": str(exc)})
        if command == "refresh-secrets":
            resolver = getattr(self.core, "resolver", None)
            if resolver is None or not hasattr(resolver, "clear_cache"):
                return json.dumps({"ok": False, "error": "no resolver to refresh"})
            resolver.clear_cache()
            self.audit.emit("secrets.refreshed")
            return json.dumps({"ok": True, "message": "cached credentials dropped"})
        return json.dumps({"ok": False, "error": f"unknown command {command!r}"})

    def serve_in_thread(self) -> threading.Thread:
        thread = threading.Thread(target=self.serve_forever, name="broker", daemon=True)
        thread.start()
        return thread

    def server_close(self) -> None:  # noqa: D102
        super().server_close()
        try:
            self.socket_path.unlink(missing_ok=True)
        except OSError:
            pass


def send_command(socket_path: Path, token: str, command: str, timeout: float = 30.0) -> dict:
    """Send one control message to a running broker and return its answer."""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(str(socket_path))
    except OSError as exc:
        raise BrokerError(f"broker unavailable at {socket_path}: {exc.strerror}") from exc
    try:
        _send_frame(sock, json.dumps({"token": token, "command": command}).encode())
        return json.loads(_recv_frame(sock))
    finally:
        sock.close()


class BrokerClientProtocol:
    """What the mitmproxy addon depends on. Two implementations below."""

    def call(self, request: BrokerRequest) -> BrokerResponse:  # pragma: no cover - interface
        raise NotImplementedError


class UnixBrokerClient(BrokerClientProtocol):
    """Connects to the broker process. One short-lived connection per call.

    Short-lived on purpose: the addon is concurrent, and a per-call connection
    avoids sharing a socket across flows (and avoids a stuck flow blocking
    every other one).
    """

    def __init__(self, socket_path: Path, token: str, timeout: float = 60.0) -> None:
        self.socket_path = socket_path
        self.token = token
        self.timeout = timeout

    def call(self, request: BrokerRequest) -> BrokerResponse:
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect(str(self.socket_path))
        except OSError as exc:
            raise BrokerError(f"broker unavailable at {self.socket_path}: {exc.strerror}") from exc
        try:
            payload = json.dumps({"token": self.token, "request": json.loads(request.to_json())})
            _send_frame(sock, payload.encode())
            return BrokerResponse.from_dict(json.loads(_recv_frame(sock)))
        finally:
            sock.close()


class InProcessBrokerClient(BrokerClientProtocol):
    """Calls the core directly. For tests, and for ``--broker inline`` runs."""

    def __init__(self, core: BrokerCore) -> None:
        self.core = core

    def call(self, request: BrokerRequest) -> BrokerResponse:
        return self.core.handle(request)
