"""Performing the authenticated request on behalf of the guest.

Two properties matter here and both are enforced in this file:

* **The connection goes where we validated it goes.** The hostname is resolved
  and policy-checked on the trusted side, and the socket is then pinned to that
  address while TLS still verifies the certificate against the *name*. A second
  resolution cannot land somewhere else (DNS rebinding), because there is no
  second resolution.
* **A redirect never carries the credential off-origin.** Every hop is
  re-checked against policy, and the credential headers are dropped the moment
  the origin changes.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import urllib.parse
from dataclasses import dataclass, field
from typing import Iterable

from ..config import DEFAULT_MAX_REDIRECTS, DEFAULT_UPSTREAM_TIMEOUT
from ..errors import PolicyDenied, UpstreamError
from ..netpolicy import Destination, DestinationPolicy, check_redirect, resolve_and_validate

#: Never forwarded in either direction - they describe *this* hop only.
HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
        "expect",
    }
)

#: Response headers that would hand the guest credential material or a way
#: around the gateway.
#:
#: WWW-Authenticate is not one of them, though it used to be listed here. It
#: carries a challenge, not a credential - the realm and scheme a client should
#: use - and the guest cannot act on it with anything but a placeholder, which
#: the broker refuses to inject outside the capability's bound host, path and
#: method. Removing it broke auth negotiation wholesale: a registry replies to
#: /v2/ with 401 and the realm to get a token from, so a client that never sees
#: it cannot proceed and reports "authentication required" against a registry
#: that is answering correctly.
STRIP_RESPONSE_HEADERS = frozenset(
    {
        "set-cookie",
        "set-cookie2",
        "proxy-authenticate",  # about *this* hop; the guest must not answer it
        "authentication-info",
        "alt-svc",  # would advertise an HTTP/3 endpoint we do not control
        "public-key-pins",
    }
)


@dataclass
class UpstreamResponse:
    status_code: int
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    final_url: str = ""
    redirects: int = 0
    truncated: bool = False


def _build_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # The guest's session CA is irrelevant here: upstream trust is the Mac's
    # normal trust store, never anything the sandbox generated.
    return ctx


def clean_headers(headers: Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
    return [(k, v) for k, v in headers if k.lower() not in HOP_BY_HOP]


class UpstreamExecutor:
    """Executes one request, following validated redirects."""

    def __init__(
        self,
        policy: DestinationPolicy,
        *,
        timeout: float = DEFAULT_UPSTREAM_TIMEOUT,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.policy = policy
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.ssl_context = ssl_context or _build_ssl_context()

    # -- connection ---------------------------------------------------------

    def _connect(self, dest: Destination) -> http.client.HTTPConnection:
        ips = resolve_and_validate(dest.host)
        pinned = str(ips[0])

        if dest.scheme == "https":
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                dest.host, dest.port, timeout=self.timeout, context=self.ssl_context
            )
        else:
            conn = http.client.HTTPConnection(dest.host, dest.port, timeout=self.timeout)

        # Pin the socket to the address we just validated. The hostname is
        # still what TLS verifies and what goes in the Host header.
        def _create_connection(address, timeout=None, source_address=None):  # noqa: ANN001
            return socket.create_connection((pinned, dest.port), timeout=self.timeout)

        conn._create_connection = _create_connection  # type: ignore[attr-defined]
        return conn

    # -- request ------------------------------------------------------------

    def execute(
        self,
        dest: Destination,
        method: str,
        target: str,
        headers: list[tuple[str, str]],
        body: bytes,
        credential_headers: list[tuple[str, str]],
        max_bytes: int,
    ) -> UpstreamResponse:
        current = dest
        current_target = target
        current_method = method.upper()
        carry_credentials = True
        redirects = 0

        while True:
            self.policy.check(current)
            send_headers = clean_headers(headers)
            if carry_credentials:
                send_headers = send_headers + list(credential_headers)
            send_headers.append(("Host", _host_header(current)))
            # `if body` used to gate this, so an empty POST - `body == b""`,
            # falsy - got no Content-Length at all: `clean_headers` had
            # already stripped whatever the guest sent (Content-Length is
            # hop-by-hop here precisely because it must be recomputed for
            # whatever body we actually forward), and nothing put it back.
            # A strict frontend refused it outright: 411 Length Required,
            # which is the correct response to a POST with neither
            # Content-Length nor Transfer-Encoding.
            if current_method not in ("GET", "HEAD"):
                send_headers.append(("Content-Length", str(len(body))))

            response = self._round_trip(
                current, current_method, current_target, send_headers, body, max_bytes
            )

            if response.status_code in (301, 302, 303, 307, 308) and redirects < self.max_redirects:
                location = _header(response.headers, "location")
                if not location:
                    return response
                nxt_dest, nxt_target = _resolve_location(current, current_target, location)
                try:
                    same = check_redirect(current, nxt_dest, self.policy)
                except PolicyDenied as denied:
                    raise UpstreamError(
                        f"redirect to a forbidden destination ({denied.reason})"
                    ) from denied
                # Off-origin hops continue without the credential, never with.
                carry_credentials = carry_credentials and same
                if response.status_code == 303 or (
                    response.status_code in (301, 302) and current_method == "POST"
                ):
                    current_method = "GET"
                    body = b""
                current, current_target = nxt_dest, nxt_target
                redirects += 1
                continue

            response.redirects = redirects
            response.final_url = f"{current.origin}{current_target}"
            return response

    def _round_trip(
        self,
        dest: Destination,
        method: str,
        target: str,
        headers: list[tuple[str, str]],
        body: bytes,
        max_bytes: int,
    ) -> UpstreamResponse:
        conn = self._connect(dest)
        try:
            conn.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
            for name, value in headers:
                conn.putheader(name, value)
            conn.endheaders(body if body and method not in ("GET", "HEAD") else None)
            raw = conn.getresponse()
            # Read one byte past the ceiling so we can tell "exactly at the
            # limit" from "over the limit".
            payload = raw.read(max_bytes + 1)
            truncated = len(payload) > max_bytes
            if truncated:
                payload = payload[:max_bytes]
            return UpstreamResponse(
                status_code=raw.status,
                headers=[(k, v) for k, v in raw.getheaders()],
                body=payload,
                truncated=truncated,
            )
        except (ssl.SSLError, ssl.CertificateError) as exc:
            raise UpstreamError(f"upstream tls failure: {type(exc).__name__}") from exc
        except (OSError, http.client.HTTPException) as exc:
            raise UpstreamError(f"upstream connection failed: {type(exc).__name__}") from exc
        finally:
            conn.close()


def _host_header(dest: Destination) -> str:
    default = 443 if dest.scheme == "https" else 80
    return dest.host if dest.port == default else f"{dest.host}:{dest.port}"


def _header(headers: Iterable[tuple[str, str]], name: str) -> str | None:
    for k, v in headers:
        if k.lower() == name:
            return v
    return None


def _resolve_location(
    current: Destination, current_target: str, location: str
) -> tuple[Destination, str]:
    base = f"{current.origin}{current_target}"
    absolute = urllib.parse.urljoin(base, location.strip())
    parsed = urllib.parse.urlsplit(absolute)
    scheme = (parsed.scheme or current.scheme).lower()
    if scheme not in ("http", "https"):
        raise UpstreamError(f"refusing redirect to {scheme!r} scheme")
    host = parsed.hostname or current.host
    port = parsed.port or (443 if scheme == "https" else 80)
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    return Destination(scheme, host, port), target


def sanitize_response_headers(headers: Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
    """Drop credential-bearing and gateway-evading response headers."""
    out = []
    for name, value in headers:
        lower = name.lower()
        if lower in STRIP_RESPONSE_HEADERS or lower in HOP_BY_HOP:
            continue
        out.append((name, value))
    return out
