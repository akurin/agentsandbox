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
from datetime import UTC, datetime
from typing import Any

from botocore.auth import S3SigV4Auth, SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

from ..audit import AuditLog, NullAuditLog, fingerprint, redactor
from ..capabilities import Capability, CapabilityStore, find_placeholders
from ..config import CAPABILITY_PREFIX
from ..errors import BrokerError, PolicyDenied, UpstreamError
from ..keychain import SecretResolver
from ..netpolicy import Destination, DestinationPolicy
from .upstream import (
    HOP_BY_HOP,
    UpstreamExecutor,
    _host_header,
    sanitize_response_headers,
)

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

#: Extra headers dropped only when re-signing for sigv4. These describe the
#: guest's *own* (unsigned, or differently-signed) request; carrying a stale
#: one alongside the freshly computed signature would either get included in
#: SignedHeaders with the wrong value or simply lie about the payload.
#:
#: `x-amz-sdk-checksum-algorithm` and `x-amz-trailer` are part of the same
#: lie even though neither is itself a checksum *value*: they are S3's own
#: separate (and separately enforced) integrity feature, layered on top of
#: signing rather than part of it, and they announce a checksum/trailer for
#: the guest's original body. Once the body is substituted and the actual
#: `x-amz-checksum-*` value is gone, an algorithm name with nothing to back
#: it up isn't harmless leftover metadata - S3 rejects it outright
#: ("specified, but no corresponding x-amz-checksum-* or x-amz-trailer
#: headers were found").
SIGV4_STALE_HEADERS = frozenset(
    {
        "x-amz-date",
        "date",
        "x-amz-content-sha256",
        "x-amz-sdk-checksum-algorithm",
        "x-amz-trailer",
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
        executor: UpstreamExecutor | None = None,
    ) -> None:
        self.session_id = session_id
        self.store = store
        self.policy = policy
        self.resolver = resolver
        self.audit = audit or NullAuditLog(session_id)
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
        except BrokerError as exc:
            # A secret backend failing (Keychain item missing, a signing
            # credential file with the wrong permissions or gone stale, `pass`
            # timing out on a pinentry prompt) is not a policy decision about
            # this request - it is the broker failing to do its job. Left
            # uncaught, this killed the connection outright: the guest saw
            # "broker unavailable" for what was actually a precise, fixable
            # error sitting one exception up.
            response = denial("secret_unavailable", str(exc), status=502, cap_id=cap.cap_id if cap else "")

        self.audit.emit(
            "broker.response" if response.decision == "allow" else "broker.denied",
            cap_id=response.cap_id or (cap.cap_id if cap else ""),
            label=cap.label if cap else "",
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
            f"on the host: asbx cap renew {cap.cap_id} {flag} <seconds> "
            f"--box {self.session_id}"
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
        self._reject_leaked_placeholders(req, cap)
        self._reject_username_mismatch(req, cap)

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

    def _reject_leaked_placeholders(self, req: BrokerRequest, cap: Capability) -> None:
        """A capability belongs in a header, nowhere else - with one exception.

        In a URL it ends up in server logs, referrers and browser history; in a
        body it may be persisted by the upstream service. Both are refused
        rather than quietly rewritten, so the agent gets a clear error.

        ``sigv4`` is the one kind that legitimately puts the placeholder in the
        body: that is the whole point of it (a signed API, like CloudFormation,
        that wants the secret as a request parameter, not a header), and
        ``_perform`` substitutes and re-signs before anything leaves. Every
        other injection kind still refuses this outright.
        """
        if find_placeholders(req.target):
            raise PolicyDenied(
                "capability_in_url",
                "put the capability in a request header, not in the URL",
            )
        if cap.injection.kind == "sigv4":
            return
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

        if cap.injection.kind == "sigv4":
            body, headers = self._sign_sigv4(req, cap, secret)
            credential_headers: list[tuple[str, str]] = []
        else:
            body = req.body
            credential_headers = build_credential_headers(cap, secret)
            headers = [
                (name, value)
                for name, value in req.headers
                if name.lower() not in STRIP_REQUEST_HEADERS
                and name.lower() not in HOP_BY_HOP
                and CAPABILITY_PREFIX not in value
            ]
            # Identity encoding keeps the response body scannable, so a
            # credential echoed back by the upstream cannot slip through
            # compressed.
            headers = [h for h in headers if h[0].lower() != "accept-encoding"]
            headers.append(("Accept-Encoding", "identity"))

        self.audit.emit(
            "broker.request",
            cap_id=cap.cap_id,
            label=cap.label,
            method=req.method,
            host=req.host,
            path=req.path,
            body_bytes=len(body),
            flow=req.flow_id,
        )

        upstream = self.executor.execute(
            req.dest,
            req.method,
            req.target,
            headers,
            body,
            credential_headers,
            cap.max_response_bytes,
        )

        if upstream.truncated:
            self.store.record_usage(cap, cap.max_response_bytes)
            raise PolicyDenied(
                "response_too_large",
                f"upstream response exceeded {cap.max_response_bytes} bytes",
            )

        resp_body = scrub_secret(upstream.body, secret)
        resp_headers = [
            (k, v)
            for k, v in sanitize_response_headers(upstream.headers)
            if secret not in v and CAPABILITY_PREFIX not in v
        ]
        resp_headers.append(("Content-Length", str(len(resp_body))))
        resp_headers.append(("X-Asbx-Decision", "allow"))
        if upstream.redirects:
            resp_headers.append(("X-Asbx-Redirects", str(upstream.redirects)))

        self.store.record_usage(cap, len(resp_body))
        return BrokerResponse(
            status_code=upstream.status_code,
            headers=resp_headers,
            body=resp_body,
            decision="allow",
            cap_id=cap.cap_id,
        )

    def _sign_sigv4(
        self, req: BrokerRequest, cap: Capability, secret: str
    ) -> tuple[bytes, list[tuple[str, str]]]:
        """Substitute the placeholder into the body and re-sign with SigV4.

        Uses ``botocore``'s own signer rather than a hand-rolled one - this is
        security-critical code, and there is no reason to re-derive a
        canonical-request algorithm AWS already publishes a reference
        implementation of. The credential used to sign is ``injection.
        signing_secret``, never the guest's own AWS environment: the broker
        only ever authenticates with a credential the profile named.
        """
        spec = cap.injection
        assert spec.signing_secret is not None and spec.region and spec.service

        # Fetched fresh, not through the cached `fetch()`: this is exactly the
        # credential most likely to carry its own expiration outside the
        # resolver's control - an STS session from `aws configure
        # export-credentials`, refreshed on disk by a job the broker knows
        # nothing about.
        raw = self.resolver.fetch_fresh(spec.signing_secret)
        try:
            bundle = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise PolicyDenied(
                "invalid_signing_secret",
                "sigv4 signing_secret must resolve to a JSON credential bundle",
            ) from exc

        # Both the shape this profile format documents (snake_case) and the
        # shape `aws configure export-credentials`/a `credential_process`
        # actually emits (PascalCase) are accepted, so a host-side refresh
        # job can write that command's output to a file verbatim.
        access_key_id = _bundle_field(bundle, "access_key_id", "AccessKeyId")
        secret_access_key = _bundle_field(bundle, "secret_access_key", "SecretAccessKey")
        session_token = _bundle_field(bundle, "session_token", "SessionToken") or None
        if not access_key_id or not secret_access_key:
            raise PolicyDenied(
                "invalid_signing_secret",
                "sigv4 signing_secret needs access_key_id/AccessKeyId and "
                "secret_access_key/SecretAccessKey",
            )
        expiration = _bundle_field(bundle, "expiration", "Expiration")
        if expiration and _is_past(expiration):
            raise PolicyDenied(
                "signing_secret_expired",
                f"the sigv4 signing credential expired at {expiration}",
            )
        for value in (access_key_id, secret_access_key, session_token):
            if value:
                redactor.register_secret(str(value))

        body = req.body.replace(req.capability.encode(), secret.encode())

        headers = [
            (name, value)
            for name, value in req.headers
            if name.lower() not in STRIP_REQUEST_HEADERS
            and name.lower() not in HOP_BY_HOP
            and name.lower() not in SIGV4_STALE_HEADERS
            and not name.lower().startswith("x-amz-checksum-")
            and CAPABILITY_PREFIX not in value
        ]
        headers = [h for h in headers if h[0].lower() != "accept-encoding"]
        headers.append(("Accept-Encoding", "identity"))
        # Pinned explicitly, matching what `UpstreamExecutor` will actually
        # send: the signature must cover the exact Host header that reaches
        # AWS, and the URL alone is an unreliable way to derive it (a literal
        # ":443" in the URL changes the signature even though it is the
        # default port and no real request would carry it).
        headers.append(("Host", _host_header(req.dest)))

        aws_request = AWSRequest(
            method=req.method,
            url=f"{req.dest.origin}{req.target}",
            data=body,
            headers=dict(headers),
        )
        credentials = Credentials(access_key_id, secret_access_key, session_token)
        signer_cls = S3SigV4Auth if spec.service == "s3" else SigV4Auth
        signer_cls(credentials, spec.service, spec.region).add_auth(aws_request)

        return body, list(aws_request.headers.items())


def _bundle_field(bundle: dict, *names: str) -> str:
    """First non-empty value among a set of alternative key names.

    A signing credential bundle may come from this profile format's own
    snake_case convention or straight from `aws configure
    export-credentials`'s PascalCase - both name the same four things.
    """
    for name in names:
        value = bundle.get(name)
        if value:
            return str(value)
    return ""


def _is_past(timestamp: str) -> bool:
    """Has an ISO-8601 timestamp already passed? Unparsable is not our call
    to make - AWS will reject a bad signature regardless, and guessing here
    would only turn a clear denial into a confusing one."""
    try:
        deadline = datetime.fromisoformat(timestamp)
    except ValueError:
        return False
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=UTC)
    return datetime.now(UTC) >= deadline


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
