"""The mitmproxy addon: policy at the network boundary.

Loaded by ``mitmdump --mode wireguard`` (see :mod:`agentsandbox.proxy.launcher`),
this addon sees every flow the guest produces and decides one of three things:

* **broker it** - the request carries a capability placeholder, so it is handed
  to the secrets broker, which performs it with the real credential;
* **forward it** - unauthenticated traffic to an allowlisted destination;
* **kill it** - everything else, which is the default.

The addon never sees a real credential and never needs to: it forwards a
normalised request and receives a sanitised response.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import logging
import os
from typing import Any

from mitmproxy import ctx, dns, http, tcp, udp
from mitmproxy.net.dns import response_codes
from mitmproxy.proxy import server_hooks

# Absolute imports: mitmdump loads this file as a top-level script, not as a
# package member, so relative imports would fail. The launcher puts the src
# root on PYTHONPATH.
from agentsandbox.audit import AuditLog, redactor
from agentsandbox.broker.core import BrokerRequest, BrokerResponse
from agentsandbox.broker.server import BrokerClientProtocol, UnixBrokerClient, read_token
from agentsandbox.capabilities import CapabilityStore, find_placeholders
from agentsandbox.config import CAPABILITY_PREFIX, TUNNEL_DNS_ADDR, SessionPaths
from agentsandbox.errors import BrokerError, PolicyDenied
from agentsandbox.netpolicy import (
    Destination,
    DestinationPolicy,
    classify_ip,
    filter_dns_answers,
    resolve_and_validate,
)
from agentsandbox.session import Session

#: Request headers a capability may legitimately arrive in. Anywhere else and
#: the placeholder is treated as a leak (URLs and bodies get logged upstream).
CAPABILITY_HEADERS = ("authorization", "x-api-key", "api-key", "x-auth-token", "authentication")

_BODY_SCAN_LIMIT = 1 * 1024 * 1024

#: Options that, if set, create traffic paths this addon never sees. An empty
#: regex in any of them matches every host, so "cleared" and "matches
#: everything" look identical in a config file - hence the explicit check.
UNINSPECTED_OPTIONS = ("ignore_hosts", "allow_hosts", "tcp_hosts", "udp_hosts")


def uninspected_option_problems(option_values: dict[str, Any]) -> list[str]:
    """Report options that would let traffic bypass inspection."""
    problems = []
    for name in UNINSPECTED_OPTIONS:
        value = option_values.get(name) or []
        if value:
            rendered = ", ".join(repr(v) for v in value)
            problems.append(
                f"{name}={rendered} would create uninspected traffic paths"
                + (" (an empty pattern matches every host)" if "" in value else "")
            )
    return problems


class SandboxAddon:
    """Enforces session policy and brokers authenticated requests."""

    def __init__(
        self,
        session: Session,
        broker: BrokerClientProtocol,
        store: CapabilityStore | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self.session = session
        self.policy: DestinationPolicy = session.policy
        self.broker = broker
        self.store = store
        self.audit = audit or AuditLog(session.paths.audit_log, session.session_id)

    def running(self) -> None:
        """Refuse to run in a configuration that would bypass this addon.

        Fail closed at start-up rather than silently pass traffic through
        uninspected - the failure mode this guards against looks exactly like
        a working sandbox from the outside.
        """
        values = {name: list(getattr(ctx.options, name, []) or []) for name in UNINSPECTED_OPTIONS}
        problems = uninspected_option_problems(values)
        if problems:
            for problem in problems:
                logging.error(f"agentsandbox: refusing to run - {problem}")
            self.audit.emit("proxy.refused_to_start", problems=problems)
            ctx.master.shutdown()

    # -- HTTP ---------------------------------------------------------------

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.response is not None:  # already answered by another addon
            return
        req = flow.request
        dest = Destination(req.scheme.lower(), req.pretty_host.lower(), req.port)

        placeholder, location = self._find_capability(flow)

        if placeholder is None:
            self._forward_or_kill(flow, dest)
            return

        if location != "header":
            self._deny(
                flow,
                "capability_misplaced",
                f"a capability must be sent in a request header, not in the {location}",
                dest=dest,
            )
            return

        self._broker(flow, dest, placeholder)

    # There is deliberately no `response` hook on the pass-through path.
    #
    # It used to scrub set-cookie, alt-svc and www-authenticate from every
    # unbrokered response, and none of that was holding anything up:
    #
    # * alt-svc advertises an HTTP/3 endpoint, and `udp_start` below already
    #   kills raw UDP - allow_raw_udp defaults to False - so the attempt dies
    #   at the policy whether or not the guest ever sees the header;
    # * public-key-pins is ignored by everything current, and a client that did
    #   honour it would fail against our CA - stripping it helped the guest, it
    #   did not protect the host;
    # * the auth headers broke credentials the broker knows nothing about, and
    #   did so inconsistently, since requests on this path are not filtered at
    #   all.
    #
    # What contains this path is the destination policy, the capability
    # bindings, and the fact that raw TCP and UDP are refused. None of that is
    # a header.
    #
    # Brokered responses are a different case and are still sanitised, in
    # `broker.upstream`: there the broker authenticated with a real credential,
    # and a session cookie coming back would be one the guest could spend on
    # any path or method - outside everything the capability restricts.

    # -- non-HTTP -----------------------------------------------------------

    def tcp_start(self, flow: tcp.TCPFlow) -> None:
        """Raw TCP we cannot inspect: killed unless the session opts in."""
        if _is_tunnel_dns(flow.server_conn.address):
            # DNS over TCP: resolvers fall back to it whenever a UDP answer is
            # truncated, so killing it here shows up as intermittent - and in
            # systemd-resolved's case, total - resolution failure.
            return
        if not self.policy.allow_raw_tcp:
            self.audit.emit(
                "net.raw_tcp_blocked",
                dst=_address(flow.server_conn.address),
                reason="raw_tcp_denied",
            )
            flow.kill()

    def udp_start(self, flow: udp.UDPFlow) -> None:
        if _is_tunnel_dns(flow.server_conn.address):
            # The tunnel's own resolver. It is mitmproxy itself, not a
            # destination the guest is reaching, and the policy that matters
            # for it is applied in `dns_request` below. Killing it here would
            # break every name lookup in the guest.
            return
        if not self.policy.allow_raw_udp:
            self.audit.emit(
                "net.raw_udp_blocked",
                dst=_address(flow.server_conn.address),
                reason="raw_udp_denied",
            )
            flow.kill()

    # -- DNS ----------------------------------------------------------------

    def dns_request(self, flow: dns.DNSFlow) -> None:
        """Refuse names the guest is not allowed to reach.

        Resolution itself happens on the host (mitmproxy's DNS mode), which is
        what "resolve and validate DNS on the trusted side" asks for; this hook
        adds the policy half.
        """
        question = flow.request.question
        if question is None:
            return
        name = question.name.rstrip(".").lower()
        try:
            self.policy.check(Destination("https", name, 443), resolve=False)
        except PolicyDenied as denied:
            self.audit.emit("dns.refused", name=name, reason=denied.reason)
            flow.response = flow.request.fail(response_codes.REFUSED)

    def dns_response(self, flow: dns.DNSFlow) -> None:
        """Strip answers pointing into blocked address space.

        A hostile upstream nameserver answering ``api.example.com -> 127.0.0.1``
        gets nothing useful through: the guest is never told the address, and
        the broker would re-validate it anyway.
        """
        if flow.response is None:
            return
        answers = flow.response.answers
        pairs = [(a.name, _record_address(a)) for a in answers]
        _, dropped = filter_dns_answers([(n, a) for n, a in pairs if a])
        if not dropped:
            return
        dropped_addrs = {a for _, a in dropped}
        flow.response.answers = [
            a for a, (_, addr) in zip(answers, pairs) if not addr or addr not in dropped_addrs
        ]
        self.audit.emit(
            "dns.answers_filtered",
            name=flow.request.question.name if flow.request.question else "",
            dropped=sorted(dropped_addrs),
        )

    # -- connections --------------------------------------------------------

    def server_connect(self, data: server_hooks.ServerConnectionHookData) -> None:
        """Second enforcement point, on the address actually being dialled.

        The ``request`` hook checked a *name*; this checks the address the
        proxy is about to connect to, which closes the window where a name
        re-resolves to something private between the two.
        """
        address = data.server.address
        if not address:
            return
        if _is_tunnel_dns(address):
            # Same reasoning as in `udp_start`: 10.0.0.53 is inside the tunnel
            # network we otherwise refuse, but it *is* the proxy's own DNS
            # responder rather than somewhere the guest can reach.
            return
        host, port = address[0], address[1]
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            try:
                resolve_and_validate(host)
            except PolicyDenied as denied:
                data.server.error = f"blocked by sandbox policy: {denied.reason}"
                self.audit.emit("net.connect_blocked", dst=f"{host}:{port}", reason=denied.reason)
            return
        reason = classify_ip(ip)
        if reason:
            data.server.error = f"blocked by sandbox policy: {reason}"
            self.audit.emit("net.connect_blocked", dst=f"{host}:{port}", reason=reason)

    # -- internals ----------------------------------------------------------

    def _find_capability(self, flow: http.HTTPFlow) -> tuple[str | None, str]:
        """Locate a capability placeholder and where it was carried."""
        req = flow.request
        for name in CAPABILITY_HEADERS:
            value = req.headers.get(name)
            if value:
                found = find_placeholders(value)
                if found:
                    return found[0], "header"
                # `curl -u user:cap_v1_...` base64-encodes the credentials, so
                # the placeholder is invisible in the raw header. Look inside,
                # otherwise every basic-auth tool needs rewriting to use a
                # bearer token it does not otherwise want.
                if placeholder := _placeholder_in_basic_auth(value):
                    return placeholder, "header"
        for name, value in req.headers.items(multi=True):
            if CAPABILITY_PREFIX in value:
                if name.lower() == "cookie":
                    return (find_placeholders(value) or [None])[0], "cookie"
                found = find_placeholders(value)
                if found:
                    return found[0], "header"
        if CAPABILITY_PREFIX in req.path:
            found = find_placeholders(req.path)
            if found:
                return found[0], "url"
        content = req.raw_content or b""
        if content and len(content) <= _BODY_SCAN_LIMIT:
            found = find_placeholders(content.decode("utf-8", "ignore"))
            if found:
                return found[0], "body"
        return None, ""

    def _forward_or_kill(self, flow: http.HTTPFlow, dest: Destination) -> None:
        try:
            self.policy.check(dest)
        except PolicyDenied as denied:
            self._deny(flow, denied.reason, denied.message, dest=dest)
            return
        self.audit.emit(
            "net.forward",
            method=flow.request.method,
            host=dest.host,
            path=flow.request.path.split("?", 1)[0],
            http_version=flow.request.http_version,
        )

    def _broker(self, flow: http.HTTPFlow, dest: Destination, placeholder: str) -> None:
        req = flow.request
        broker_request = BrokerRequest(
            session_id=self.session.session_id,
            capability=placeholder,
            method=req.method,
            scheme=dest.scheme,
            host=dest.host,
            port=dest.port,
            target=req.path,
            headers=[(k, v) for k, v in req.headers.items(multi=True)],
            body=req.raw_content or b"",
            operation=req.headers.get("x-asbx-operation"),
            flow_id=flow.id,
        )
        try:
            response = self.broker.call(broker_request)
        except BrokerError as exc:
            # Fail closed: if the broker is unreachable, nothing is authorised.
            self.audit.emit("broker.unavailable", host=dest.host, error=str(exc))
            self._deny(flow, "broker_unavailable", "the secrets broker is not available", dest=dest)
            return
        flow.response = _to_mitm_response(response)

    def _deny(
        self,
        flow: http.HTTPFlow,
        reason: str,
        message: str,
        *,
        dest: Destination | None = None,
        status: int = 403,
    ) -> None:
        self.audit.emit(
            "net.denied",
            reason=reason,
            method=flow.request.method,
            host=dest.host if dest else flow.request.pretty_host,
            path=flow.request.path.split("?", 1)[0],
        )
        body = (
            f'{{"error": "sandbox_policy", "reason": "{reason}", '
            f'"message": {_json_str(message)}}}'
        ).encode()
        flow.response = http.Response.make(
            status,
            body,
            {
                "Content-Type": "application/json",
                "X-Asbx-Decision": "deny",
                "X-Asbx-Reason": reason,
            },
        )


def _json_str(value: str) -> str:
    import json

    return json.dumps(redactor.text(value))


def _to_mitm_response(response: BrokerResponse) -> http.Response:
    headers = [(k.encode(), v.encode()) for k, v in response.headers if k.lower() != "content-length"]
    made = http.Response.make(response.status_code, response.body, {})
    made.headers.clear()
    for key, value in headers:
        made.headers.add(key, value)
    made.headers["content-length"] = str(len(response.body))
    return made


def _placeholder_in_basic_auth(header_value: str) -> str | None:
    """Find a capability inside ``Authorization: Basic base64(user:pass)``.

    Tools that speak basic auth - curl -u, requests' auth=, half of every CI
    script - encode the password before it reaches the wire. Without this, a
    placeholder in the password position looks like opaque base64 and the
    request is forwarded with a credential the upstream will reject.

    The *username* here is deliberately ignored: which account a capability
    uses is fixed when it is issued, not chosen by the guest.
    """
    scheme, _, encoded = header_value.partition(" ")
    if scheme.lower() != "basic" or not encoded:
        return None
    try:
        decoded = base64.b64decode(encoded.strip(), validate=True).decode("utf-8", "replace")
    except (ValueError, binascii.Error):
        return None
    found = find_placeholders(decoded)
    return found[0] if found else None


def _is_tunnel_dns(address: Any) -> bool:
    """Is this mitmproxy's own DNS responder inside the tunnel?

    Narrow on purpose - exactly that address, exactly port 53. The rest of the
    tunnel network stays unreachable to the guest, and the names this resolver
    will answer are still filtered by `dns_request`/`dns_response`.
    """
    if not address or len(address) < 2:
        return False
    return str(address[0]) == TUNNEL_DNS_ADDR and int(address[1]) == 53


def _address(address: Any) -> str:
    if not address:
        return "?"
    return f"{address[0]}:{address[1]}"


def _record_address(record: dns.ResourceRecord) -> str | None:
    try:
        return str(record.ipv4_address)
    except Exception:  # noqa: BLE001 - not an A record
        pass
    try:
        return str(record.ipv6_address)
    except Exception:  # noqa: BLE001 - not an AAAA record
        return None


def _load_from_environment() -> SandboxAddon:
    """Entry point used when mitmdump loads this file as a script.

    Everything comes from the session directory, which mitmproxy is pointed at
    with ``ASBX_SESSION``; nothing is passed on a command line where it could
    show up in ``ps``.
    """
    session_id = os.environ.get("ASBX_SESSION")
    if not session_id:
        raise RuntimeError("ASBX_SESSION is not set; refusing to run without a session")
    session = Session.load(session_id)
    paths: SessionPaths = session.paths
    store = CapabilityStore(paths.capabilities, session_id)
    broker: BrokerClientProtocol = UnixBrokerClient(
        paths.broker_socket, read_token(paths.broker_token)
    )
    addon = SandboxAddon(session, broker, store=store)
    ctx.log.info(
        f"agentsandbox: session {session_id}, "
        f"{len(session.policy.allow_hosts)} allowed host pattern(s)"
    )
    return addon


if os.environ.get("ASBX_SESSION"):  # pragma: no cover - exercised by mitmdump
    addons = [_load_from_environment()]
else:
    addons = []
