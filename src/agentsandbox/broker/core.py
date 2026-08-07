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
import re
import secrets
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from botocore.auth import S3SigV4Auth, SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

from ..audit import AuditLog, NullAuditLog, fingerprint, redactor
from ..capabilities import (
    AwsAutosignSpec,
    Capability,
    CapabilityStore,
    find_placeholders,
)
from ..config import CAPABILITY_PREFIX, DEFAULT_MAX_RESPONSE_BYTES
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

#: Identity-bearing headers a SigV4 signature produces - dropped off-origin
#: on a redirect via the same `credential_headers`/`carry_credentials`
#: mechanism every other injection kind already gets. Everything else SigV4
#: touches (Host, X-Amz-Content-Sha256, ...) carries no authority on its own
#: and travels as an ordinary header.
SIGV4_CREDENTIAL_HEADER_NAMES = frozenset({"authorization", "x-amz-date", "x-amz-security-token"})

_SIGV4_CREDENTIAL_SCOPE_RE = re.compile(
    r"Credential=[^/\s,]+/\d{8}/([A-Za-z0-9-]+)/([a-z0-9-]+)/aws4_request"
)


def _parse_sigv4_scope(auth_header: str) -> tuple[str, str] | None:
    """Pull ``(region, service)`` out of a SigV4 Authorization header's
    credential scope - valid or not, the scope names what the signer
    intended to sign for."""
    match = _SIGV4_CREDENTIAL_SCOPE_RE.search(auth_header)
    if not match:
        return None
    return match.group(1), match.group(2)


def _split_signed_headers(
    signed: list[tuple[str, str]],
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """``(headers, credential_headers)`` - separate what a SigV4 signature
    depends on from everything else, so a redirect can drop the former
    off-origin exactly as it already does for every other injection kind."""
    credential_headers = [(k, v) for k, v in signed if k.lower() in SIGV4_CREDENTIAL_HEADER_NAMES]
    headers = [(k, v) for k, v in signed if k.lower() not in SIGV4_CREDENTIAL_HEADER_NAMES]
    return headers, credential_headers

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
    #: No capability, no placeholder: the guest signed with its session's
    #: dummy AWS credential (see `AwsAutosignSpec`), and this gets re-signed
    #: wholesale with the session's own signing secret, regardless of
    #: destination.
    aws_autosign: bool = False

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
                "aws_autosign": self.aws_autosign,
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
            aws_autosign=bool(data.get("aws_autosign", False)),
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
        aws_autosign: AwsAutosignSpec | None = None,
    ) -> None:
        self.session_id = session_id
        self.store = store
        self.policy = policy
        self.resolver = resolver
        self.audit = audit or NullAuditLog(session_id)
        self.executor = executor or UpstreamExecutor(policy)
        self.aws_autosign = aws_autosign

    # -- entry point --------------------------------------------------------

    def handle(self, req: BrokerRequest) -> BrokerResponse:
        started = time.monotonic()
        cap: Capability | None = None
        try:
            if req.capability:
                cap = self._resolve(req)
                self._authorize(req, cap)
                if cap.injection.kind == "body":
                    response = self._perform_body(req, cap)
                else:
                    response = self._perform(req, cap)
            elif req.aws_autosign:
                if self.aws_autosign is None:
                    raise PolicyDenied(
                        "aws_autosign_disabled",
                        "this session has no AWS auto-sign credential configured",
                    )
                response = self._perform_aws_autosign(req)
            else:
                # Not reachable through the addon - it only calls in with a
                # capability, or with aws_autosign=True, never neither. Kept
                # as an explicit failure rather than falling through, for
                # whatever else constructs a BrokerRequest directly.
                raise PolicyDenied(
                    "empty_request", "request carries neither a capability nor an aws_autosign marker"
                )
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
        """A capability belongs in a header, with one deliberate exception.

        In a URL it ends up in server logs, referrers and browser history -
        always refused, no matter the capability's kind. In a body it may be
        persisted by the upstream service, which is normally exactly what
        must not happen - refused rather than quietly rewritten, so the agent
        gets a clear error - *unless* the capability was explicitly issued
        with injection.kind "body", where persisting it upstream is the
        entire point (a secret meant to end up embedded in content the guest
        constructs, not presented back by the guest itself).
        """
        if find_placeholders(req.target):
            raise PolicyDenied(
                "capability_in_url",
                "put the capability in a request header, not in the URL",
            )
        if cap.injection.kind == "body":
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
            body_bytes=len(req.body),
            flow=req.flow_id,
        )

        upstream = self.executor.execute(
            req.dest,
            req.method,
            req.target,
            headers,
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

    def _perform_body(self, req: BrokerRequest, cap: Capability) -> BrokerResponse:
        """Body-kind capability: the placeholder is meant to end up embedded
        in content the guest constructs (a CloudFormation template's Lambda
        env var, say), not presented back by the guest itself.

        Substituted here, into the raw body, before anything is forwarded -
        and before any aws_autosign re-signing below, since a SigV4
        signature has to cover the bytes that actually go out, not the
        placeholder version. The same request can need both: a `cdk deploy`
        asset upload is dummy-signed by the guest's own AWS credential *and*
        may carry a body-kind capability's placeholder in its content.
        """
        secret = self.resolver.fetch(cap.secret)
        redactor.register_secret(secret)
        body = req.body.replace(req.capability.encode(), secret.encode())

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

        if req.aws_autosign:
            if self.aws_autosign is None:
                raise PolicyDenied(
                    "aws_autosign_disabled",
                    "this session has no AWS auto-sign credential configured",
                )
            credentials, region, service = self._resolve_aws_signing_credentials(req)
            signed_headers, credential_headers = self._sign_aws_request(
                req, body, region, service, credentials
            )
            upstream = self.executor.execute(
                req.dest,
                req.method,
                req.target,
                signed_headers,
                body,
                credential_headers,
                cap.max_response_bytes,
            )
            upstream.body = scrub_minted_credentials(upstream.body, self.aws_autosign.access_key_id)
        else:
            # A SigV4-shaped Authorization header that isn't this session's
            # aws_autosign marker means the guest is authenticating with some
            # other AWS credential asbx does not control - a leaked real one,
            # or a differently-configured profile the guest picked up on its
            # own. Modifying the body invalidates whatever signature covers
            # it regardless of whose credential produced it, so stripping
            # Authorization below (as every other body-kind request does)
            # would silently discard a credential that might otherwise have
            # worked, and forward an unauthenticated request that fails
            # upstream for a reason with nothing to do with this capability.
            # Refuse with the real explanation instead.
            auth_header = next((v for k, v in req.headers if k.lower() == "authorization"), "")
            if auth_header.startswith("AWS4-HMAC-SHA256 "):
                raise PolicyDenied(
                    "body_injection_conflicts_with_aws_signature",
                    "this request is signed with an AWS credential this session's "
                    "aws_autosign does not control - modifying the body would "
                    "invalidate that signature. The guest must sign AWS requests "
                    "with its own dummy AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY for "
                    "aws_autosign to re-sign them, not a separately configured "
                    "profile or cached login session.",
                )
            headers = [
                (name, value)
                for name, value in req.headers
                if name.lower() not in STRIP_REQUEST_HEADERS
                and name.lower() not in HOP_BY_HOP
                and CAPABILITY_PREFIX not in value
            ]
            headers = [h for h in headers if h[0].lower() != "accept-encoding"]
            headers.append(("Accept-Encoding", "identity"))
            upstream = self.executor.execute(
                req.dest,
                req.method,
                req.target,
                headers,
                body,
                [],
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

    def _resolve_aws_signing_credentials(
        self, req: BrokerRequest
    ) -> tuple[Credentials, str, str]:
        """Fetch and validate the aws_autosign signing credential, and read
        off the region/service to sign for.

        ``region``/``service`` come from the guest's own (necessarily
        invalid) credential scope rather than a declared table - the guest's
        SDK already worked those out correctly to build the request, it just
        had nothing real to sign with.
        """
        assert self.aws_autosign is not None  # checked by callers

        auth_header = next((v for k, v in req.headers if k.lower() == "authorization"), "")
        scope = _parse_sigv4_scope(auth_header)
        if scope is None:
            raise PolicyDenied(
                "aws_autosign_unparseable",
                "could not find a service/region to sign with in the guest's own Authorization header",
            )
        region, service = scope

        # Fetched fresh, not through the cached `fetch()`: this is exactly the
        # credential most likely to carry its own expiration outside the
        # resolver's control - an STS session from `aws configure
        # export-credentials`, refreshed on disk by a job the broker knows
        # nothing about.
        raw = self.resolver.fetch_fresh(self.aws_autosign.signing_secret)
        try:
            bundle = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise PolicyDenied(
                "invalid_signing_secret",
                "aws_autosign signing_secret must resolve to a JSON credential bundle",
            ) from exc

        # Both this profile format's own snake_case convention and the shape
        # `aws configure export-credentials`/a `credential_process` actually
        # emits (PascalCase) are accepted, so a host-side refresh job can
        # write that command's output to a file verbatim.
        access_key_id = _bundle_field(bundle, "access_key_id", "AccessKeyId")
        secret_access_key = _bundle_field(bundle, "secret_access_key", "SecretAccessKey")
        session_token = _bundle_field(bundle, "session_token", "SessionToken") or None
        if not access_key_id or not secret_access_key:
            raise PolicyDenied(
                "invalid_signing_secret",
                "aws_autosign signing_secret needs access_key_id/AccessKeyId and "
                "secret_access_key/SecretAccessKey",
            )
        expiration = _bundle_field(bundle, "expiration", "Expiration")
        if expiration and _is_past(expiration):
            raise PolicyDenied(
                "signing_secret_expired",
                f"the aws_autosign signing credential expired at {expiration}",
            )
        for value in (access_key_id, secret_access_key, session_token):
            if value:
                redactor.register_secret(str(value))

        return Credentials(access_key_id, secret_access_key, session_token), region, service

    def _sign_aws_request(
        self,
        req: BrokerRequest,
        body: bytes,
        region: str,
        service: str,
        credentials: Credentials,
    ) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
        """Sign ``body`` for the given scope and split the result into
        ordinary headers and credential-bearing ones.

        ``body`` is taken as a parameter rather than read from ``req``
        because a body-kind capability substitutes into it first - the
        signature must cover the bytes that actually go out, not whatever
        placeholder the guest built the request with.
        """
        headers = [
            (name, value)
            for name, value in req.headers
            if name.lower() not in STRIP_REQUEST_HEADERS
            and name.lower() not in HOP_BY_HOP
            and name.lower() not in SIGV4_STALE_HEADERS
            and not name.lower().startswith("x-amz-checksum-")
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
        signer_cls = S3SigV4Auth if service == "s3" else SigV4Auth
        signer_cls(credentials, service, region).add_auth(aws_request)
        return _split_signed_headers(list(aws_request.headers.items()))

    def _perform_aws_autosign(self, req: BrokerRequest) -> BrokerResponse:
        """No capability, no placeholder: the guest signed with its session's
        dummy AWS credential (it has no real one), so any request carrying it
        gets re-signed wholesale with the session's ``aws_autosign.
        signing_secret``, regardless of destination.

        This can't be abused to sign something it shouldn't: the real
        destination is still policy-checked below, and a claimed scope that
        doesn't match what AWS expects for that destination just gets
        rejected by AWS's own verification.
        """
        assert self.aws_autosign is not None  # checked by the caller
        self.policy.check(req.dest)

        credentials, region, service = self._resolve_aws_signing_credentials(req)
        signed_headers, credential_headers = self._sign_aws_request(
            req, req.body, region, service, credentials
        )

        self.audit.emit(
            "broker.aws_autosign",
            method=req.method,
            host=req.host,
            path=req.path,
            service=service,
            region=region,
            flow=req.flow_id,
        )

        upstream = self.executor.execute(
            req.dest,
            req.method,
            req.target,
            signed_headers,
            req.body,
            credential_headers,
            DEFAULT_MAX_RESPONSE_BYTES,
        )
        upstream.body = scrub_minted_credentials(upstream.body, self.aws_autosign.access_key_id)
        if upstream.truncated:
            raise PolicyDenied(
                "response_too_large",
                f"upstream response exceeded {DEFAULT_MAX_RESPONSE_BYTES} bytes",
            )

        headers_out = list(sanitize_response_headers(upstream.headers))
        headers_out.append(("Content-Length", str(len(upstream.body))))
        headers_out.append(("X-Asbx-Decision", "allow"))
        if upstream.redirects:
            headers_out.append(("X-Asbx-Redirects", str(upstream.redirects)))
        return BrokerResponse(
            status_code=upstream.status_code,
            headers=headers_out,
            body=upstream.body,
            decision="allow",
        )


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


def scrub_minted_credentials(body: bytes, dummy_access_key_id: str) -> bytes:
    """Replace a real, independently-usable AWS credential minted by a
    re-signed request with the session's own dummy marker, before the
    response reaches the guest.

    A dummy-signed ``sts:AssumeRole`` (or ``GetSessionToken``, or similar)
    re-signed with the real ``aws_autosign.signing_secret`` can genuinely
    succeed - the real profile may well be allowed to assume the role the
    guest asked for - and AWS's answer is then a fresh, fully-working
    temporary credential. Forwarded as-is, that credential lets the guest
    authenticate directly for every subsequent call, bypassing the broker
    entirely - the whole point of ``aws_autosign`` undone in one response.

    ``AssumeRole`` itself is not denied: tooling that depends on it
    succeeding (the CDK CLI falls back to its base credential gracefully
    when it fails, but plenty of other tools do not) keeps working. Only
    ``AccessKeyId`` is rewritten to the session's *existing* dummy marker
    rather than a freshly minted one - `_looks_like_dummy_aws_request`
    already recognises it, in the addon process, with no new state to
    synchronise across that boundary - and ``SecretAccessKey``/
    ``SessionToken`` become meaningless values, since the broker never
    verifies the guest's own signature, only the access key.

    Not scoped to STS or to ``AssumeRole`` by name: any AWS-autosigned
    response carrying a ``Credentials`` element (matched by local name,
    ignoring the namespace prefix) with these three children is scrubbed,
    regardless of which service or action produced it - Cognito Identity's
    ``GetCredentialsForIdentity`` has the same shape under a different
    service. A response with no such element - the overwhelming majority,
    ``GetCallerIdentity``, every S3 call, ... - passes through byte-for-byte
    unchanged, as does a malformed or non-XML body.
    """
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return body

    changed = False
    for elem in root.iter():
        if elem.tag.rpartition("}")[-1] != "Credentials":
            continue
        for child in elem:
            replacement = {
                "AccessKeyId": dummy_access_key_id,
                "SecretAccessKey": secrets.token_urlsafe(30),
                "SessionToken": secrets.token_urlsafe(60),
            }.get(child.tag.rpartition("}")[-1])
            if replacement is not None:
                child.text = replacement
                changed = True

    if not changed:
        return body
    return ET.tostring(root, encoding="utf-8")


def scrub_secret(body: bytes, secret: str) -> bytes:
    """Remove any echo of the real credential from what goes back to the guest.

    Some APIs return the token they were called with (token introspection,
    error messages, ``/user`` style endpoints). The guest must never receive it.
    """
    if not secret:
        return body
    return body.replace(secret.encode(), b"[redacted]")
