"""Broker request handling.

``BrokerCore.handle`` is a pure function of its inputs plus the capability
store: no sockets, no mitmproxy types.  That is deliberate - it is the piece
that decides whether a real credential gets used, so it has to be testable
directly, and the transport (:mod:`agentsandbox.broker.server`) is a thin shell
around it.

Order of checks is the order of the spec's flow, and every step fails closed.
"""

from __future__ import annotations

import base64
import binascii
import json
import time
from dataclasses import dataclass, field
from typing import Any

from ..audit import AuditLog, NullAuditLog, fingerprint, redactor
from ..capabilities import Capability, CapabilityStore, find_placeholders
from ..config import CAPABILITY_PREFIX
from ..errors import PolicyDenied, UpstreamError
from ..keychain import SecretResolver
from ..netpolicy import Destination, DestinationPolicy
from .approvals import ApprovalGate, ApprovalRequest, DenyAll
from .upstream import HOP_BY_HOP, UpstreamExecutor, sanitize_response_headers

#: Request headers we never forward: the guest's own idea of authentication is
#: replaced by the broker's, and cookies are not a channel we support.
STRIP_REQUEST_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "x-amz-security-token",
        "x-goog-api-key",
        "authentication",
    }
)

_BODY_SCAN_LIMIT = 1 * 1024 * 1024


@dataclass
class BrokerRequest:
    session_id: str
    capability: str
    method: str
    scheme: str
    host: str
    port: int
    target: str  # path plus query, as sent on the wire
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    operation: str | None = None
    flow_id: str = ""

    @property
    def dest(self) -> Destination:
        return Destination(self.scheme.lower(), self.host.lower(), self.port)

    @property
    def path(self) -> str:
        return self.target.split("?", 1)[0]

    def to_json(self) -> str:
        return json.dumps(
            {
                "session_id": self.session_id,
                "capability": self.capability,
                "method": self.method,
                "scheme": self.scheme,
                "host": self.host,
                "port": self.port,
                "target": self.target,
                "headers": [list(h) for h in self.headers],
                "body_b64": base64.b64encode(self.body).decode(),
                "operation": self.operation,
                "flow_id": self.flow_id,
            }
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BrokerRequest:
        return cls(
            session_id=data["session_id"],
            capability=data["capability"],
            method=data["method"],
            scheme=data["scheme"],
            host=data["host"],
            port=int(data["port"]),
            target=data["target"],
            headers=[(k, v) for k, v in data.get("headers", [])],
            body=base64.b64decode(data.get("body_b64", "")),
            operation=data.get("operation"),
            flow_id=data.get("flow_id", ""),
        )


@dataclass
class BrokerResponse:
    status_code: int
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    decision: str = "allow"
    reason: str = ""
    cap_id: str = ""

    def to_json(self) -> str:
        return json.dumps(
            {
                "status_code": self.status_code,
                "headers": [list(h) for h in self.headers],
                "body_b64": base64.b64encode(self.body).decode(),
                "decision": self.decision,
                "reason": self.reason,
                "cap_id": self.cap_id,
            }
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BrokerResponse:
        return cls(
            status_code=int(data["status_code"]),
            headers=[(k, v) for k, v in data.get("headers", [])],
            body=base64.b64decode(data.get("body_b64", "")),
            decision=data.get("decision", "allow"),
            reason=data.get("reason", ""),
            cap_id=data.get("cap_id", ""),
        )


#: Denials an operator can undo by extending the grant, mapped to the flag
#: that does it. Anything not listed here is a scope decision, and telling the
#: guest how to "fix" those would be advice on how to get around the policy.
RENEWABLE_REASONS = {"capability_expired": "--ttl"}


def denial(
    reason: str,
    message: str,
    *,
    status: int = 403,
    cap_id: str = "",
    remedy: str = "",
) -> BrokerResponse:
    """A denial the guest sees as an ordinary HTTP error.

    The message is intentionally about *policy*, never about the credential:
    it must not tell an attacker whether a capability exists, only that this
    operation is not permitted.

    ``remedy`` is the exception, and only for a capability that has simply run
    out: an expired grant is otherwise indistinguishable from a broken
    credential, so an agent hitting one has no way to report anything useful
    and a human reading the audit log has to reconstruct the context by hand.
    Naming the capability and the command that extends it leaks nothing the
    holder of that capability does not already know.
    """
    payload = {"error": "sandbox_policy", "reason": reason, "message": message}
    if cap_id:
        payload["capability"] = cap_id
    if remedy:
        payload["remedy"] = remedy
    body = json.dumps(payload, indent=2).encode()
    return BrokerResponse(
        status_code=status,
        headers=[
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(body))),
            ("X-Asbx-Decision", "deny"),
            ("X-Asbx-Reason", reason),
        ],
        body=body,
        decision="deny",
        reason=reason,
        cap_id=cap_id,
    )


class BrokerCore:
    """Validates a brokered request and, if it passes, performs it upstream."""

    def __init__(
        self,
        session_id: str,
        store: CapabilityStore,
        policy: DestinationPolicy,
        resolver: SecretResolver,
        *,
        audit: AuditLog | None = None,
        approvals: ApprovalGate | None = None,
        executor: UpstreamExecutor | None = None,
    ) -> None:
        self.session_id = session_id
        self.store = store
        self.policy = policy
        self.resolver = resolver
        self.audit = audit or NullAuditLog(session_id)
        self.approvals = approvals or DenyAll()
        self.executor = executor or UpstreamExecutor(policy)

    # -- entry point --------------------------------------------------------

    def handle(self, req: BrokerRequest) -> BrokerResponse:
        started = time.monotonic()
        cap: Capability | None = None
        try:
            cap = self._resolve(req)
            self._authorize(req, cap)
            response = self._perform(req, cap)
        except PolicyDenied as denied:
            response = denial(
                denied.reason,
                denied.message,
                cap_id=cap.cap_id if cap else "",
                remedy=self._remedy(denied.reason, cap),
            )
        except UpstreamError as exc:
            response = denial("upstream_failed", str(exc), status=502, cap_id=cap.cap_id if cap else "")

        self.audit.emit(
            "broker.response" if response.decision == "allow" else "broker.denied",
            cap_id=response.cap_id or (cap.cap_id if cap else ""),
            provider=cap.provider if cap else "",
            method=req.method,
            host=req.host,
            path=req.path,
            status=response.status_code,
            reason=response.reason,
            bytes=len(response.body),
            duration_ms=round((time.monotonic() - started) * 1000, 1),
            flow=req.flow_id,
        )
        return response

    def _remedy(self, reason: str, cap: Capability | None) -> str:
        """The command that would let this request through, if one exists."""
        flag = RENEWABLE_REASONS.get(reason)
        if not flag or cap is None:
            return ""
        return (
            f"on the host: asbx --session {self.session_id} "
            f"cap renew {cap.cap_id} {flag} <seconds>"
        )

    # -- steps --------------------------------------------------------------

    def _resolve(self, req: BrokerRequest) -> Capability:
        """Find the capability, before deciding anything about it.

        Kept separate from :meth:`_authorize` so that every denial *after* this
        point can name the capability it is about. Doing the lookup inside the
        checks meant an expired grant produced a denial that identified
        nothing - which is exactly the case where the operator most needs to
        know which one to renew.
        """
        if not req.capability.startswith(CAPABILITY_PREFIX):
            raise PolicyDenied("malformed_capability", "not a capability placeholder")

        cap = self.store.lookup(req.capability)
        if cap is None:
            # Unknown placeholder: either revoked-and-pruned, forged, or from
            # another session. All three are "no".
            self.audit.emit(
                "broker.unknown_capability",
                token=fingerprint(req.capability),
                host=req.host,
                method=req.method,
            )
            raise PolicyDenied("unknown_capability", "this capability is not valid")
        return cap

    def _authorize(self, req: BrokerRequest, cap: Capability) -> None:
        # Session-wide egress policy applies before the capability's own scope:
        # a capability cannot widen where the session may talk.
        self.policy.check(req.dest)
        cap.validate(
            session_id=req.session_id,
            dest=req.dest,
            method=req.method,
            path=req.path,
            operation=req.operation,
        )
        self._reject_leaked_placeholders(req)
        self._reject_username_mismatch(req, cap)

        if cap.needs_approval(req.method):
            approval = ApprovalRequest(
                session_id=req.session_id,
                cap_id=cap.cap_id,
                provider=cap.provider,
                method=req.method.upper(),
                url=f"{req.dest.origin}{req.target}",
                reason=f"{req.method.upper()} requires approval for this capability",
                body_preview=redactor.text(req.body[:200].decode("utf-8", "replace")),
            )
            self.audit.emit(
                "broker.approval_requested",
                cap_id=cap.cap_id,
                request_id=approval.request_id,
                method=approval.method,
                host=req.host,
            )
            if not self.approvals.decide(approval):
                raise PolicyDenied("approval_denied", "the operator did not approve this operation")

    def _reject_username_mismatch(self, req: BrokerRequest, cap: Capability) -> None:
        """Check the basic-auth credentials the guest actually presented.

        The account is fixed when the capability is issued - the guest never
        gets to choose it, or a placeholder for one account could be tried
        against another. That much is deliberate.

        What is *not* deliberate is doing it silently: quietly substituting the
        right username makes a typo look like it worked, and hides the bug in
        whatever built the request. So a mismatch is an error, while an empty
        username is allowed, since plenty of token-style APIs omit it.
        """
        if cap.injection.kind != "basic":
            return
        expected = (cap.injection.username or "").strip()
        if not expected:
            return

        for name, value in req.headers:
            if name.lower() != "authorization":
                continue
            scheme, _, encoded = value.partition(" ")
            if scheme.lower() != "basic" or not encoded:
                continue
            try:
                decoded = base64.b64decode(encoded.strip(), validate=True).decode("utf-8", "replace")
            except (ValueError, binascii.Error):
                continue
            presented, _, password = decoded.partition(":")
            presented = presented.strip()
            if presented and presented != expected:
                raise PolicyDenied(
                    "username_mismatch",
                    f"this capability authenticates as {expected!r}, not {presented!r}",
                )

            # Detection is deliberately lenient - it has to find a placeholder
            # inside base64 - but anything *around* it means the request was
            # built wrong. Refusing here is also what stops the malformed value
            # from being forwarded upstream: a placeholder must never leave the
            # sandbox, even though it is not itself a credential.
            if password and password.strip() != req.capability:
                raise PolicyDenied(
                    "malformed_credential",
                    "the password must be exactly the capability placeholder, "
                    "with nothing appended",
                )

    def _reject_leaked_placeholders(self, req: BrokerRequest) -> None:
        """A capability belongs in a header, nowhere else.

        In a URL it ends up in server logs, referrers and browser history; in a
        body it may be persisted by the upstream service. Both are refused
        rather than quietly rewritten, so the agent gets a clear error.
        """
        if find_placeholders(req.target):
            raise PolicyDenied(
                "capability_in_url",
                "put the capability in a request header, not in the URL",
            )
        if len(req.body) <= _BODY_SCAN_LIMIT and find_placeholders(
            req.body.decode("utf-8", "ignore")
        ):
            raise PolicyDenied(
                "capability_in_body",
                "put the capability in a request header, not in the body",
            )

    def _perform(self, req: BrokerRequest, cap: Capability) -> BrokerResponse:
        secret = self.resolver.fetch(cap.secret)
        redactor.register_secret(secret)
        credential_headers = build_credential_headers(cap, secret)

        forward_headers = [
            (name, value)
            for name, value in req.headers
            if name.lower() not in STRIP_REQUEST_HEADERS
            and name.lower() not in HOP_BY_HOP
            and CAPABILITY_PREFIX not in value
        ]
        # Identity encoding keeps the response body scannable, so a credential
        # echoed back by the upstream cannot slip through compressed.
        forward_headers = [h for h in forward_headers if h[0].lower() != "accept-encoding"]
        forward_headers.append(("Accept-Encoding", "identity"))

        self.audit.emit(
            "broker.request",
            cap_id=cap.cap_id,
            provider=cap.provider,
            method=req.method,
            host=req.host,
            path=req.path,
            body_bytes=len(req.body),
            flow=req.flow_id,
        )

        upstream = self.executor.execute(
            req.dest,
            req.method,
            req.target,
            forward_headers,
            req.body,
            credential_headers,
            cap.max_response_bytes,
        )

        if upstream.truncated:
            self.store.record_usage(cap, cap.max_response_bytes)
            raise PolicyDenied(
                "response_too_large",
                f"upstream response exceeded {cap.max_response_bytes} bytes",
            )

        body = scrub_secret(upstream.body, secret)
        headers = [
            (k, v)
            for k, v in sanitize_response_headers(upstream.headers)
            if secret not in v and CAPABILITY_PREFIX not in v
        ]
        headers.append(("Content-Length", str(len(body))))
        headers.append(("X-Asbx-Decision", "allow"))
        if upstream.redirects:
            headers.append(("X-Asbx-Redirects", str(upstream.redirects)))

        self.store.record_usage(cap, len(body))
        return BrokerResponse(
            status_code=upstream.status_code,
            headers=headers,
            body=body,
            decision="allow",
            cap_id=cap.cap_id,
        )


def build_credential_headers(cap: Capability, secret: str) -> list[tuple[str, str]]:
    """Render the capability's injection spec into concrete headers."""
    spec = cap.injection
    spec.validate()
    if spec.kind == "bearer":
        return [("Authorization", f"Bearer {secret}")]
    if spec.kind == "basic":
        raw = f"{spec.username or ''}:{secret}".encode()
        return [("Authorization", "Basic " + base64.b64encode(raw).decode())]
    if spec.kind == "header":
        return [(spec.header, spec.template.format(secret=secret))]
    raise PolicyDenied("unsupported_injection", f"cannot inject {spec.kind!r}")


def scrub_secret(body: bytes, secret: str) -> bytes:
    """Remove any echo of the real credential from what goes back to the guest.

    Some APIs return the token they were called with (token introspection,
    error messages, ``/user`` style endpoints). The guest must never receive it.
    """
    if not secret:
        return body
    return body.replace(secret.encode(), b"[redacted]")
