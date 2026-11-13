"""SOCKS5 TCP transport and DNS over that transport.

A proxy hostname is resolved by the host before the SOCKS connection exists;
sandbox destination names are resolved through the proxy.
"""

from __future__ import annotations

import asyncio
import inspect
import ipaddress
import secrets
import socket
import ssl
import struct
import threading
import time
import urllib.parse
from dataclasses import dataclass

from mitmproxy import dns

from .errors import SessionError

_DOH_HOST = "cloudflare-dns.com"
_DOH_IP = "1.1.1.1"
_DOH_PORT = 443
_DNS_CACHE_MAX_TTL = 60


def _address(host: str, port: int) -> bytes:
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        name = host.encode("idna")
        if not name or len(name) > 255:
            raise ValueError("invalid SOCKS destination")
        return b"\x03" + bytes([len(name)]) + name + struct.pack("!H", port)
    return (b"\x01" if ip.version == 4 else b"\x04") + ip.packed + struct.pack("!H", port)


def _reply_length(kind: int) -> int:
    if kind == 1:
        return 4
    if kind == 4:
        return 16
    if kind == 3:
        return 1
    raise OSError("invalid SOCKS address type")


@dataclass(frozen=True)
class SocksEndpoint:
    host: str
    port: int
    username: str = ""
    password: str = ""

    def __post_init__(self) -> None:
        # Runtime state must stay out of dataclass fields: Box.to_dict uses
        # dataclasses.asdict, which cannot copy a thread lock.
        object.__setattr__(self, "_dns_cache", {})
        object.__setattr__(self, "_dns_response_cache", {})
        object.__setattr__(self, "_dns_cache_lock", threading.Lock())

    @classmethod
    def parse(cls, value: str) -> SocksEndpoint:
        try:
            url = urllib.parse.urlsplit(value)
            host, port = url.hostname, url.port
            if url.scheme != "socks5" or not host or not port or url.path or url.query or url.fragment:
                raise ValueError("expected socks5://HOST:PORT")
            try:
                ipaddress.ip_address(host)
            except ValueError:
                name = host.rstrip(".").encode("idna").decode("ascii")
                labels = name.split(".")
                if (len(name) > 253 or not labels or any(
                    not label or len(label) > 63 or not label[0].isalnum()
                    or not label[-1].isalnum() or any(
                        not (char.isalnum() or char == "-") for char in label
                    ) for label in labels
                )):
                    raise ValueError("invalid SOCKS proxy hostname")
            username = urllib.parse.unquote(url.username or "")
            password = urllib.parse.unquote(url.password or "")
            if len(username.encode()) > 255 or len(password.encode()) > 255:
                raise ValueError("SOCKS credentials are too long")
            if password and not username:
                raise ValueError("SOCKS password needs a username")
            return cls(host, port, username, password)
        except ValueError as exc:
            raise SessionError(f"invalid SOCKS egress: {exc}") from exc

    def to_dict(self) -> dict:
        return {"host": self.host, "port": self.port, "username": self.username,
                "password": self.password}

    def redacted(self) -> str:
        return f"socks5://{self.host}:{self.port}" + (" (authenticated)" if self.username else "")

    def url(self) -> str:
        auth = ""
        if self.username:
            auth = (urllib.parse.quote(self.username, safe="") + ":" +
                    urllib.parse.quote(self.password, safe="") + "@")
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"socks5://{auth}{host}:{self.port}"

    def connect(self, host: str, port: int, timeout: float = 30.0) -> socket.socket:
        sock = socket.create_connection((self.host, self.port), timeout=timeout)
        try:
            method = 2 if self.username else 0
            sock.sendall(bytes([5, 1, method]))
            if _recv(sock, 2) != bytes([5, method]):
                raise OSError("SOCKS authentication method rejected")
            if method == 2:
                user, password = self.username.encode(), self.password.encode()
                sock.sendall(bytes([1, len(user)]) + user + bytes([len(password)]) + password)
                if _recv(sock, 2) != b"\x01\x00":
                    raise OSError("SOCKS authentication failed")
            sock.sendall(b"\x05\x01\x00" + _address(host, port))
            header = _recv(sock, 4)
            if header[:1] != b"\x05" or header[1] != 0 or header[2] != 0:
                raise OSError("SOCKS CONNECT rejected")
            size = _reply_length(header[3])
            if header[3] == 3:
                size = _recv(sock, 1)[0]
            _recv(sock, size + 2)
            return sock
        except BaseException:
            sock.close()
            raise

    async def open_connection(self, original, host: str, port: int, **kwargs):
        if kwargs.get("ssl") or kwargs.get("sock") or kwargs.get("local_addr"):
            raise OSError("unsupported direct socket option in SOCKS egress")
        reader, writer = await original(self.host, self.port)
        try:
            method = 2 if self.username else 0
            writer.write(bytes([5, 1, method]))
            await writer.drain()
            if await reader.readexactly(2) != bytes([5, method]):
                raise OSError("SOCKS authentication method rejected")
            if method == 2:
                user, password = self.username.encode(), self.password.encode()
                writer.write(bytes([1, len(user)]) + user + bytes([len(password)]) + password)
                await writer.drain()
                if await reader.readexactly(2) != b"\x01\x00":
                    raise OSError("SOCKS authentication failed")
            writer.write(b"\x05\x01\x00" + _address(host, port))
            await writer.drain()
            header = await reader.readexactly(4)
            if header[:1] != b"\x05" or header[1] != 0 or header[2] != 0:
                raise OSError("SOCKS CONNECT rejected")
            size = _reply_length(header[3])
            if header[3] == 3:
                size = (await reader.readexactly(1))[0]
            await reader.readexactly(size + 2)
            return reader, writer
        except BaseException:
            writer.close()
            await writer.wait_closed()
            raise

    def dns_query(self, wire: bytes) -> dns.DNSMessage:
        """DoH through SOCKS, with a fixed resolver IP and normal TLS checks."""
        original_id = struct.unpack_from("!H", wire)[0]
        wire = b"\x00\x00" + wire[2:]
        cached = self._cached_dns_response(wire, original_id)
        if cached is not None:
            return cached
        sock = self.connect(_DOH_IP, _DOH_PORT, timeout=15)
        try:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=_DOH_HOST) as tls:
                request = (
                    f"POST /dns-query HTTP/1.1\r\nHost: {_DOH_HOST}\r\n"
                    "Content-Type: application/dns-message\r\nAccept: application/dns-message\r\n"
                    f"Content-Length: {len(wire)}\r\nConnection: close\r\n\r\n"
                ).encode() + wire
                tls.sendall(request)
                import http.client

                response = http.client.HTTPResponse(tls)
                response.begin()
                if response.status != 200:
                    raise OSError(f"DNS over HTTPS returned {response.status}")
                payload = response.read(65536)
                if len(payload) < 12 or len(payload) >= 65536:
                    raise OSError("invalid DNS over HTTPS response")
                answer = dns.DNSMessage.unpack(payload)
                if answer.id != 0 or answer.query:
                    raise OSError("mismatched DNS over HTTPS response")
                self._remember_dns_answer(dns.DNSMessage.unpack(wire).question, answer)
                self._remember_dns_response(wire, payload, answer)
                answer.id = original_id
                return answer
        finally:
            sock.close()

    def resolve(self, host: str) -> list[ipaddress._BaseAddress]:
        try:
            return [ipaddress.ip_address(host.strip("[]"))]
        except ValueError:
            pass
        name = host.rstrip(".").lower()
        for kind in (1, 28):
            cached = self._cached_dns_addresses(name, kind)
            if cached:
                return cached
            wire_name = b"".join(bytes([len(label)]) + label.encode("idna") for label in host.rstrip(".").split(".")) + b"\x00"
            wire = struct.pack("!HHHHHH", secrets.randbelow(65536), 0x0100, 1, 0, 0, 0) + wire_name + struct.pack("!HH", kind, 1)
            answer = self.dns_query(wire)
            out: list[ipaddress._BaseAddress] = []
            for record in answer.answers:
                if record.type == kind:
                    ip = ipaddress.ip_address(record.data)
                    if ip not in out:
                        out.append(ip)
            if out:
                return out
        raise OSError("DNS returned no addresses")

    def _cached_dns_addresses(self, name: str, kind: int) -> list[ipaddress._BaseAddress]:
        key = (name, kind)
        with self._dns_cache_lock:
            entry = self._dns_cache.get(key)
            if entry is None:
                return []
            expires_at, addresses = entry
            if time.monotonic() >= expires_at:
                del self._dns_cache[key]
                return []
            return list(addresses)

    def _cached_dns_response(self, wire: bytes, original_id: int) -> dns.DNSMessage | None:
        with self._dns_cache_lock:
            entry = self._dns_response_cache.get(wire)
            if entry is None:
                return None
            expires_at, payload = entry
            remaining = int(expires_at - time.monotonic())
            if remaining <= 0:
                del self._dns_response_cache[wire]
                return None
        answer = dns.DNSMessage.unpack(payload)
        answer.id = original_id
        for record in answer.answers:
            record.ttl = min(record.ttl, remaining)
        return answer

    def _remember_dns_response(self, wire: bytes, payload: bytes, answer: dns.DNSMessage) -> None:
        question = dns.DNSMessage.unpack(wire).question
        if (question is None or question.type not in (1, 28) or question.class_ != 1
                or not answer.answers):
            return
        ttl = min(_DNS_CACHE_MAX_TTL, *(record.ttl for record in answer.answers))
        if ttl <= 0:
            return
        with self._dns_cache_lock:
            if len(self._dns_response_cache) >= 256:
                self._dns_response_cache.clear()
            self._dns_response_cache[wire] = (time.monotonic() + ttl, payload)

    def _remember_dns_answer(self, question: dns.Question | None, answer: dns.DNSMessage) -> None:
        if question is None or question.type not in (1, 28) or question.class_ != 1:
            return
        records = [r for r in answer.answers if r.type == question.type and r.class_ == 1]
        if not records:
            return
        ttl = min(_DNS_CACHE_MAX_TTL, *(r.ttl for r in records))
        if ttl <= 0:
            return
        addresses = list(dict.fromkeys(ipaddress.ip_address(r.data) for r in records))
        with self._dns_cache_lock:
            if len(self._dns_cache) >= 256:
                self._dns_cache.clear()
            self._dns_cache[(question.name.rstrip(".").lower(), question.type)] = (
                time.monotonic() + ttl, addresses
            )


def _recv(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("SOCKS connection closed")
        data.extend(chunk)
    return bytes(data)


def install_mitm_transport(endpoint: SocksEndpoint, policy) -> None:
    """Replace mitmproxy's final TCP dial with SOCKS, including early TLS dials.

    This is deliberately at the transport boundary: HTTP request hooks run
    too late for certificate probing and cannot cover raw TCP.
    """
    from mitmproxy.proxy import server

    try:
        source = inspect.getsource(server.ConnectionHandler.open_connection)
    except (OSError, TypeError) as exc:
        raise RuntimeError("cannot verify mitmproxy TCP dial path") from exc
    if "await asyncio.open_connection(" not in source:
        raise RuntimeError("mitmproxy TCP dial path changed; refusing SOCKS egress")
    original_asyncio = server.asyncio
    if isinstance(original_asyncio, _SocksAsyncio):
        raise RuntimeError("SOCKS transport already installed")
    server.asyncio = _SocksAsyncio(original_asyncio, endpoint, policy)


class _SocksAsyncio:
    def __init__(self, module, endpoint: SocksEndpoint, policy) -> None:
        self.module = module
        self.endpoint = endpoint
        self.policy = policy

    def __getattr__(self, name):
        return getattr(self.module, name)

    async def open_connection(self, host, port, **kwargs):
        # Do not let the SOCKS server re-resolve a name after our policy
        # check. Validate the current DNS answer and pin the CONNECT to it.
        ips = await asyncio.to_thread(self.policy.resolve_and_validate, host)
        try:
            return await asyncio.wait_for(
                self.endpoint.open_connection(
                    self.module.open_connection, str(ips[0]), port, **kwargs
                ),
                timeout=30,
            )
        except (TimeoutError, asyncio.IncompleteReadError) as exc:
            raise OSError("SOCKS connection timed out or closed") from exc
