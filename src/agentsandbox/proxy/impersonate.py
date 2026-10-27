"""Sending a request upstream with a real browser's fingerprint.

mitmproxy opens its own upstream connection for every flow, with OpenSSL and
the ``h2`` library, so the destination sees mitmproxy's TLS ClientHello and
HTTP/2 framing no matter what the guest runs. Cloudflare's bot protection
fingerprints exactly those and refuses some sites to anything that is not a
browser - and, separately, to a browser fingerprint whose User-Agent says it
is something else.

For a host the profile lists under ``browser_impersonation``, the addon
(:class:`agentsandbox.proxy.addon.SandboxAddon`) checks policy as usual and
marks the flow; :class:`ImpersonatingForwarder` then performs the request
itself with curl-impersonate, and hands the guest the response. Two things
keep this path no weaker than mitmproxy's own:

* **The connection goes where policy said.** The name is resolved and
  validated here, and curl is pinned to that address with ``CURLOPT_RESOLVE``
  - the same "no second resolution" rule ``broker.upstream`` follows. The
  certificate is still verified against the name.
* **Redirects are not followed.** The guest gets the 3xx and follows it
  itself, through the proxy, where the next hop is checked like any other.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging

from mitmproxy import http

from agentsandbox.audit import AuditLog, redactor
from agentsandbox.broker.upstream import HOP_BY_HOP
from agentsandbox.config import DEFAULT_UPSTREAM_TIMEOUT
from agentsandbox.errors import PolicyDenied
from agentsandbox.netpolicy import Destination, resolve_and_validate

#: Set by the addon on a flow that passed policy and should go out this way;
#: the value is the curl_cffi impersonation target.
METADATA_KEY = "asbx_impersonate"

#: Request headers the impersonated browser supplies itself. The User-Agent
#: and client hints have to agree with the TLS fingerprint - a curl or Python
#: UA over Chrome's ClientHello is refused just the same - and curl has to own
#: Accept-Encoding, since it is curl that decodes the body.
_BROWSER_OWNED = ("user-agent", "accept-encoding")
_BROWSER_OWNED_PREFIXES = ("sec-ch-ua",)

#: Response headers describing a body or connection the guest never sees:
#: curl has already decoded the body, and mitmproxy frames it afresh.
_STRIP_RESPONSE = frozenset(
    {"content-encoding", "content-length", "transfer-encoding", "connection", "keep-alive", "alt-svc"}
)


def upstream_headers(request: http.Request) -> list[tuple[str, str]]:
    """The guest's headers, minus what this hop or the browser owns."""
    out: list[tuple[str, str]] = []
    cookies: list[str] = []
    for name, value in request.headers.items(multi=True):
        lower = name.lower()
        if lower in HOP_BY_HOP or lower in _BROWSER_OWNED or lower.startswith(_BROWSER_OWNED_PREFIXES):
            continue
        if lower == "cookie":
            # HTTP/2 allows one Cookie header per pair; curl expects one.
            cookies.append(value)
            continue
        out.append((name, value))
    if cookies:
        out.append(("cookie", "; ".join(cookies)))
    return out


def response_headers(items) -> list[tuple[bytes, bytes]]:
    return [
        (name.encode(), value.encode())
        for name, value in items
        if name.lower() not in _STRIP_RESPONSE
    ]


class ImpersonatingForwarder:
    """Performs flows the addon marked with :data:`METADATA_KEY`.

    A separate addon, listed after :class:`SandboxAddon`, so policy has
    always run first; and async, so a slow upstream holds up only its own
    flow, not every other connection mitmproxy is serving.
    """

    def __init__(self, audit: AuditLog, timeout: float = DEFAULT_UPSTREAM_TIMEOUT) -> None:
        self.audit = audit
        self.timeout = timeout

    async def request(self, flow: http.HTTPFlow) -> None:
        target = flow.metadata.get(METADATA_KEY)
        if not target or flow.response is not None:
            return
        req = flow.request
        dest = Destination(req.scheme.lower(), req.pretty_host.lower(), req.port)
        try:
            ips = await asyncio.to_thread(resolve_and_validate, dest.host)
        except PolicyDenied as denied:
            self._fail(flow, dest, 403, denied.reason, denied.message)
            return
        try:
            response = await self._fetch(req, dest, str(ips[0]), target)
        except Exception as exc:  # noqa: BLE001 - curl raises its own hierarchy
            logging.warning(f"agentsandbox: impersonated request to {dest.host} failed: {exc}")
            self._fail(flow, dest, 502, "impersonated_upstream_error", str(exc))
            return
        flow.response = response

    async def _fetch(self, req: http.Request, dest: Destination, ip: str, target: str) -> http.Response:
        from curl_cffi import CurlOpt
        from curl_cffi.requests import AsyncSession

        url_host = f"[{dest.host}]" if ":" in dest.host else dest.host
        url = f"{dest.scheme}://{url_host}:{dest.port}{req.path}"
        curl_options = {}
        if not _is_ip_literal(dest.host):
            pinned = f"[{ip}]" if ":" in ip else ip
            curl_options[CurlOpt.RESOLVE] = [f"{dest.host}:{dest.port}:{pinned}"]
        # One session per request: a shared one would pool connections across
        # pinned addresses and keep a cookie jar the guest knows nothing about.
        async with AsyncSession(curl_options=curl_options) as session:
            upstream = await session.request(
                req.method,
                url,
                headers=upstream_headers(req),
                data=req.raw_content or None,
                impersonate=target,
                allow_redirects=False,
                timeout=self.timeout,
                discard_cookies=True,
            )
        body = redactor.scrub_body(upstream.content)
        made = http.Response.make(upstream.status_code, body, response_headers(upstream.headers.multi_items()))
        made.headers["content-length"] = str(len(body))
        self.audit.emit(
            "net.forward",
            method=req.method,
            host=dest.host,
            path=req.path.split("?", 1)[0],
            http_version=req.http_version,
            impersonate=target,
            status=upstream.status_code,
        )
        return made

    def _fail(self, flow: http.HTTPFlow, dest: Destination, status: int, reason: str, message: str) -> None:
        denied = status == 403
        self.audit.emit(
            "net.denied" if denied else "net.impersonate_failed",
            reason=reason,
            method=flow.request.method,
            host=dest.host,
            path=flow.request.path.split("?", 1)[0],
        )
        body = json.dumps(
            {
                "error": "sandbox_policy" if denied else "upstream_error",
                "reason": reason,
                "message": redactor.text(message),
            }
        ).encode()
        flow.response = http.Response.make(
            status,
            body,
            {
                "Content-Type": "application/json",
                "X-Asbx-Decision": "deny" if denied else "error",
                "X-Asbx-Reason": reason,
            },
        )


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True
