"""The capability model.

A capability is *not* a secret the guest can spend elsewhere - it is a
reference to permission the broker holds.  The guest sees only

    cap_v1_<random>

and the store keeps nothing but a SHA-256 of that string, so a leaked store
file does not yield working placeholders, and the audit log can refer to a
capability by its short id without ever printing the token.

Every capability is bound to the axes the spec lists: session, provider and
account, hostnames, resources, methods and semantic operations, an optional
expiry, and whether a human must approve.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import secrets
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .config import (
    CAPABILITY_PREFIX,
    DEFAULT_MAX_RESPONSE_BYTES,
    DEFAULT_TTL_SECONDS,
    write_private_file,
)
from .errors import CapabilityError, PolicyDenied
from .netpolicy import Destination, any_host_matches

#: Injection strategies the broker knows how to perform safely. Anything else
#: is refused rather than approximated - "deny unsupported authenticated
#: protocols by default".
SUPPORTED_INJECTIONS = frozenset({"bearer", "header", "basic"})

#: Methods that change state and therefore need explicit approval by default.
MUTATING_METHODS = ("POST", "PUT", "PATCH", "DELETE")


def new_placeholder() -> str:
    """Mint a fresh placeholder token for the guest."""
    return CAPABILITY_PREFIX + secrets.token_urlsafe(24)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def short_id(token_hash_hex: str) -> str:
    """Stable public id used in logs and CLI output."""
    return "cap-" + token_hash_hex[:12]


@dataclass
class SecretRef:
    """Where the *real* credential lives. Never the credential itself."""

    backend: str = "keychain"  # keychain | pass | env | file
    service: str = ""
    account: str = ""
    #: Which store to look in, when the backend has more than one. For ``pass``
    #: this is ``PASSWORD_STORE_DIR`` - the way to keep a project's secrets in
    #: their own database, under their own GPG key.
    store: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> SecretRef:
        return cls(
            backend=data.get("backend", "keychain"),
            service=data.get("service", ""),
            account=data.get("account", ""),
            store=data.get("store", ""),
        )


@dataclass
class InjectionSpec:
    """How the broker attaches the credential to the upstream request."""

    kind: str = "bearer"
    header: str = "Authorization"
    template: str = "Bearer {secret}"
    username: str | None = None  # basic auth only

    def validate(self) -> None:
        if self.kind not in SUPPORTED_INJECTIONS:
            raise PolicyDenied(
                "unsupported_injection",
                f"injection kind {self.kind!r} is not supported",
            )
        if self.kind == "header" and "{secret}" not in self.template:
            raise PolicyDenied("invalid_injection", "header template must contain {secret}")

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> InjectionSpec:
        return cls(
            kind=data.get("kind", "bearer"),
            header=data.get("header", "Authorization"),
            template=data.get("template", "Bearer {secret}"),
            username=data.get("username"),
        )


@dataclass
class Capability:
    token_hash: str
    session_id: str
    provider: str
    account: str = ""
    hosts: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=lambda: ["GET", "HEAD"])
    path_globs: list[str] = field(default_factory=lambda: ["/*"])
    #: Checked before ``path_globs``, so a broad allow can keep a few specific
    #: endpoints out of reach - the destructive corner of an API you otherwise
    #: want open.
    deny_path_globs: list[str] = field(default_factory=list)
    operations: list[str] = field(default_factory=list)
    secret: SecretRef = field(default_factory=SecretRef)
    injection: InjectionSpec = field(default_factory=InjectionSpec)
    expires_at: float = 0.0
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    approval_required_methods: list[str] = field(default_factory=lambda: list(MUTATING_METHODS))
    revoked: bool = False
    used_requests: int = 0
    used_bytes: int = 0
    created_at: float = field(default_factory=time.time)
    label: str = ""

    # -- identity -----------------------------------------------------------

    @property
    def cap_id(self) -> str:
        return short_id(self.token_hash)

    # -- validation ---------------------------------------------------------

    def check_alive(self, now: float | None = None) -> None:
        now = time.time() if now is None else now
        if self.revoked:
            raise PolicyDenied("capability_revoked", "capability has been revoked")
        if self.expires_at and now >= self.expires_at:
            raise PolicyDenied("capability_expired", "capability has expired")

    def check_session(self, session_id: str) -> None:
        if session_id != self.session_id:
            # A capability that leaked to another session is worthless.
            raise PolicyDenied("wrong_session", "capability does not belong to this session")

    def check_destination(self, dest: Destination) -> None:
        if not any_host_matches(dest.host, self.hosts):
            raise PolicyDenied("host_not_permitted", "capability does not cover this host")
        if dest.scheme.lower() != "https":
            raise PolicyDenied("insecure_scheme", "credentials are only attached over https")

    def check_operation(self, method: str, path: str, operation: str | None = None) -> None:
        method = method.upper()
        if method not in {m.upper() for m in self.methods}:
            raise PolicyDenied("method_not_permitted", f"{method} is not permitted")
        path_only = path.split("?", 1)[0]
        # Deny wins, and is checked first: the point of the list is to carve
        # exceptions out of a permissive allow.
        if any(fnmatch.fnmatchcase(path_only, glob) for glob in self.deny_path_globs):
            raise PolicyDenied("path_denied", "this path is explicitly denied")
        if not any(fnmatch.fnmatchcase(path_only, glob) for glob in self.path_globs):
            raise PolicyDenied("path_not_permitted", "path is not permitted")
        if self.resources and not any(res_matches(r, path_only) for r in self.resources):
            raise PolicyDenied("resource_not_permitted", "path is outside the bound resources")
        if self.operations and operation is not None and operation not in self.operations:
            raise PolicyDenied("operation_not_permitted", f"operation {operation} is not permitted")

    def needs_approval(self, method: str) -> bool:
        return method.upper() in {m.upper() for m in self.approval_required_methods}

    def validate(
        self,
        *,
        session_id: str,
        dest: Destination,
        method: str,
        path: str,
        operation: str | None = None,
        now: float | None = None,
    ) -> None:
        """Full check. Raises :class:`PolicyDenied` on the first failure."""
        self.check_alive(now)
        self.check_session(session_id)
        self.check_destination(dest)
        self.check_operation(method, path, operation)
        self.injection.validate()

    # -- serialisation ------------------------------------------------------

    def to_dict(self) -> dict:
        data = asdict(self)
        data["secret"] = self.secret.to_dict()
        data["injection"] = self.injection.to_dict()
        return data

    @classmethod
    def from_dict(cls, data: dict) -> Capability:
        data = dict(data)
        data["secret"] = SecretRef.from_dict(data.get("secret", {}))
        data["injection"] = InjectionSpec.from_dict(data.get("injection", {}))
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})

    def public_view(self) -> dict:
        """What is safe to show a human: no token, no secret material."""
        return {
            "cap_id": self.cap_id,
            "session": self.session_id,
            "provider": self.provider,
            "account": self.account,
            "label": self.label,
            "hosts": self.hosts,
            "resources": self.resources,
            "methods": self.methods,
            "paths": self.path_globs,
            "denied_paths": self.deny_path_globs,
            "operations": self.operations,
            "expires_at": self.expires_at,
            "expires_in": max(0, int(self.expires_at - time.time())) if self.expires_at else None,
            "requests": self.used_requests,
            "bytes": self.used_bytes,
            "approval_for": self.approval_required_methods,
            "revoked": self.revoked,
        }


def res_matches(resource: str, path: str) -> bool:
    """Match a bound resource against a request path.

    Resources are written as ``type:identifier`` (``repo:acme/api``,
    ``bucket:builds``); the identifier must appear as a path segment run. This
    keeps ``repo:acme/api`` from matching ``/acme/api-secrets``.
    """
    ident = resource.split(":", 1)[-1].strip("/")
    if not ident:
        return False
    padded = path if path.endswith("/") else path + "/"
    return f"/{ident}/" in padded


@dataclass
class CapabilitySpec:
    """What a caller asks for when minting a capability."""

    provider: str
    hosts: list[str]
    account: str = ""
    resources: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=lambda: ["GET", "HEAD"])
    path_globs: list[str] = field(default_factory=lambda: ["/*"])
    deny_path_globs: list[str] = field(default_factory=list)
    operations: list[str] = field(default_factory=list)
    secret: SecretRef = field(default_factory=SecretRef)
    injection: InjectionSpec = field(default_factory=InjectionSpec)
    ttl_seconds: int = DEFAULT_TTL_SECONDS
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    approval_required_methods: list[str] | None = None
    label: str = ""
    #: Environment variable the placeholder is delivered as inside the guest,
    #: e.g. ``GITHUB_TOKEN``. Without this the operator has to copy the
    #: placeholder by hand, and it changes every session.
    env_var: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> CapabilitySpec:
        spec = cls(
            provider=data["provider"],
            hosts=list(data.get("hosts", [])),
            account=data.get("account", ""),
            resources=list(data.get("resources", [])),
            methods=list(data.get("methods", ["GET", "HEAD"])),
            path_globs=list(data.get("path_globs", data.get("paths", ["/*"]))),
            deny_path_globs=list(data.get("deny_paths", [])),
            operations=list(data.get("operations", [])),
            secret=SecretRef.from_dict(data.get("secret", {})),
            injection=InjectionSpec.from_dict(data.get("injection", {})),
            ttl_seconds=int(data.get("ttl_seconds", DEFAULT_TTL_SECONDS)),
            max_response_bytes=int(data.get("max_response_bytes", DEFAULT_MAX_RESPONSE_BYTES)),
            approval_required_methods=data.get("approval_required_methods"),
            label=data.get("label", ""),
        )
        if not spec.hosts:
            raise CapabilityError("a capability must be bound to at least one host")
        return spec


class CapabilityStore:
    """Per-session capability store, persisted as a 0600 JSON file.

    Only hashes are written. The store is reloaded when the file changes on
    disk so the CLI can mint a capability while the broker is running.
    """

    def __init__(self, path: Path, session_id: str) -> None:
        self.path = path
        self.session_id = session_id
        self._caps: dict[str, Capability] = {}
        self._mtime: float = -1.0
        self._lock = threading.RLock()
        self._load()

    # -- persistence --------------------------------------------------------

    def _load(self) -> None:
        with self._lock:
            if not self.path.exists():
                self._caps = {}
                self._mtime = -1.0
                return
            mtime = self.path.stat().st_mtime
            if mtime == self._mtime:
                return
            raw = json.loads(self.path.read_text() or "{}")
            self._caps = {
                h: Capability.from_dict(d) for h, d in raw.get("capabilities", {}).items()
            }
            self._mtime = mtime

    def _save(self) -> None:
        with self._lock:
            payload = {
                "session": self.session_id,
                "capabilities": {h: c.to_dict() for h, c in self._caps.items()},
            }
            write_private_file(self.path, json.dumps(payload, indent=2, sort_keys=True))
            self._mtime = self.path.stat().st_mtime

    def reload_if_changed(self) -> None:
        if not self.path.exists():
            return
        if self.path.stat().st_mtime != self._mtime:
            self._load()

    # -- lifecycle ----------------------------------------------------------

    def issue(self, spec: CapabilitySpec) -> tuple[str, Capability]:
        """Mint a capability. Returns ``(placeholder, capability)``.

        The placeholder is returned exactly once; the store cannot reproduce
        it later.
        """
        spec.injection.validate()
        token = new_placeholder()
        cap = Capability(
            token_hash=token_hash(token),
            session_id=self.session_id,
            provider=spec.provider,
            account=spec.account,
            hosts=list(spec.hosts),
            resources=list(spec.resources),
            methods=[m.upper() for m in spec.methods],
            path_globs=list(spec.path_globs),
            deny_path_globs=list(spec.deny_path_globs),
            operations=list(spec.operations),
            secret=spec.secret,
            injection=spec.injection,
            expires_at=(time.time() + spec.ttl_seconds) if spec.ttl_seconds else 0.0,
            max_response_bytes=spec.max_response_bytes,
            approval_required_methods=(
                list(spec.approval_required_methods)
                if spec.approval_required_methods is not None
                else list(MUTATING_METHODS)
            ),
            label=spec.label,
        )
        with self._lock:
            self._load()
            self._caps[cap.token_hash] = cap
            self._save()
        return token, cap

    def lookup(self, token: str) -> Capability | None:
        """Constant-time-ish lookup by placeholder value."""
        with self._lock:
            self.reload_if_changed()
            return self._caps.get(token_hash(token))

    def get(self, cap_id: str) -> Capability | None:
        with self._lock:
            self.reload_if_changed()
            for cap in self._caps.values():
                if cap.cap_id == cap_id:
                    return cap
            return None

    def list(self) -> list[Capability]:
        with self._lock:
            self.reload_if_changed()
            return sorted(self._caps.values(), key=lambda c: c.created_at)

    def revoke(self, cap_id: str) -> bool:
        with self._lock:
            self._load()
            for cap in self._caps.values():
                if cap.cap_id == cap_id:
                    cap.revoked = True
                    self._save()
                    return True
            return False

    def renew(self, cap_id: str, *, ttl_seconds: int) -> Capability | None:
        """Extend a capability that has expired, or push its expiry out.

        ``ttl_seconds`` is measured from now, not from the old expiry: renewing
        something that lapsed overnight should give a fresh window, not a
        window that is already half spent.  Zero means it stops expiring.

        The usage counters are deliberately not touched - they are what the
        audit log is for, and a capability that has been renewed four times
        should look like it.

        Revoked capabilities are not renewable: revocation is a decision, not
        a timeout.  Returns the updated capability, or ``None`` if there is no
        such capability.
        """
        with self._lock:
            self._load()
            for cap in self._caps.values():
                if cap.cap_id != cap_id:
                    continue
                if cap.revoked:
                    raise CapabilityError(
                        f"capability {cap_id} was revoked; issue a new one instead"
                    )
                cap.expires_at = (time.time() + ttl_seconds) if ttl_seconds else 0.0
                self._save()
                return cap
            return None

    def revoke_all(self) -> int:
        with self._lock:
            self._load()
            count = 0
            for cap in self._caps.values():
                if not cap.revoked:
                    cap.revoked = True
                    count += 1
            self._save()
            return count

    def destroy(self) -> None:
        """Wipe the store entirely - used when a session is torn down."""
        with self._lock:
            self._caps = {}
            if self.path.exists():
                # Overwrite before unlinking so a recovered inode is useless.
                size = self.path.stat().st_size
                with open(self.path, "r+b") as fh:
                    fh.write(b"\x00" * size)
                    fh.flush()
                    os.fsync(fh.fileno())
                self.path.unlink()
            self._mtime = -1.0

    def record_usage(self, cap: Capability, response_bytes: int) -> None:
        with self._lock:
            self._load()
            stored = self._caps.get(cap.token_hash)
            if stored is None:
                return
            stored.used_requests += 1
            stored.used_bytes += max(0, response_bytes)
            cap.used_requests = stored.used_requests
            cap.used_bytes = stored.used_bytes
            self._save()

    def prune_expired(self, now: float | None = None) -> int:
        now = time.time() if now is None else now
        with self._lock:
            self._load()
            dead = [h for h, c in self._caps.items() if c.expires_at and c.expires_at <= now]
            for h in dead:
                del self._caps[h]
            if dead:
                self._save()
            return len(dead)


def find_placeholders(text: str) -> list[str]:
    """Extract every capability placeholder occurring in a string."""
    import re

    pattern = re.compile(rf"{re.escape(CAPABILITY_PREFIX)}[A-Za-z0-9_\-]{{16,}}")
    return pattern.findall(text)


def contains_placeholder(values: Iterable[Any]) -> bool:
    return any(CAPABILITY_PREFIX in str(v) for v in values)
