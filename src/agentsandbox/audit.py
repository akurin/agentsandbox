"""Audit logging with redaction applied on the way in, not on the way out.

The rule from the spec is absolute: capabilities, authorization headers,
cookies and real credentials never reach a log line.  This module is the single
place that writes audit records, so redaction cannot be forgotten by a caller
that formats its own message.

Two layers of defence:

1. *Structural* - header names on :data:`SENSITIVE_HEADERS` are dropped wholesale,
   never pattern-matched.
2. *Literal and pattern* - any string value is scanned for registered secret
   literals (real credentials the broker has handled) and for well-known
   credential shapes, including our own ``cap_v1_`` placeholders.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Iterable

from .config import CAPABILITY_PREFIX, ensure_private_dir

REDACTED = "[redacted]"

#: Header names whose *value* is never logged, in any form.
SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "www-authenticate",
        "proxy-authenticate",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "x-amz-security-token",
        "x-goog-api-key",
        "x-csrf-token",
        "authentication",
    }
)

#: Shapes that look like credentials regardless of where they appear.
_CREDENTIAL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(rf"{re.escape(CAPABILITY_PREFIX)}[A-Za-z0-9_\-]{{8,}}"),
    re.compile(r"\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{16,}"),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    re.compile(r"\bey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"),
    re.compile(r"(?i)\b(?:bearer|basic|token)\s+[A-Za-z0-9._\-+/=]{12,}"),
)

_MAX_VALUE_LEN = 512


def fingerprint(value: str) -> str:
    """Stable, non-reversible id for a secret, safe to log and correlate on."""
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:16]


class Redactor:
    """Scrubs secrets from anything on its way into a log record."""

    def __init__(self) -> None:
        self._literals: set[str] = set()
        self._lock = threading.Lock()

    def register_secret(self, value: str | None) -> None:
        """Remember a literal secret so it is scrubbed if it ever shows up.

        Kept in memory only - the set is never serialised anywhere.
        """
        if value and len(value) >= 6:
            with self._lock:
                self._literals.add(value)

    def forget_all(self) -> None:
        with self._lock:
            self._literals.clear()

    def text(self, value: str) -> str:
        with self._lock:
            literals = sorted(self._literals, key=len, reverse=True)
        for literal in literals:
            if literal in value:
                value = value.replace(literal, REDACTED)
        for pattern in _CREDENTIAL_PATTERNS:
            value = pattern.sub(REDACTED, value)
        if len(value) > _MAX_VALUE_LEN:
            value = value[:_MAX_VALUE_LEN] + f"...[+{len(value) - _MAX_VALUE_LEN}B]"
        return value

    def headers(self, headers: Iterable[tuple[str, str]]) -> list[list[str]]:
        out: list[list[str]] = []
        for name, value in headers:
            if name.lower() in SENSITIVE_HEADERS:
                out.append([name, REDACTED])
            else:
                out.append([name, self.text(value)])
        return out

    def value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            return {
                k: (REDACTED if str(k).lower() in SENSITIVE_HEADERS else self.value(v))
                for k, v in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [self.value(v) for v in value]
        if isinstance(value, (int, float, bool)) or value is None:
            return value
        return self.text(str(value))


#: Process-wide redactor. The broker registers every credential it unlocks.
redactor = Redactor()


class AuditLog:
    """Append-only JSONL audit trail, one file per session, mode 0600.

    Bodies are never stored - only sizes and hashes - which also keeps this
    from becoming the "mitmproxy flow dump" the spec forbids.
    """

    def __init__(self, path: Path, session_id: str = "-") -> None:
        self.path = path
        self.session_id = session_id
        self._lock = threading.Lock()
        ensure_private_dir(path.parent)

    def emit(self, event: str, **fields: Any) -> dict[str, Any]:
        record = {
            "ts": time.time(),
            "session": self.session_id,
            "event": event,
            **{k: redactor.value(v) for k, v in fields.items()},
        }
        line = json.dumps(record, sort_keys=True, default=str) + "\n"
        with self._lock:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, line.encode())
            finally:
                os.close(fd)
        return record

    def read(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self.path.open() as fh:
            return [json.loads(line) for line in fh if line.strip()]


class NullAuditLog(AuditLog):
    """For unit tests and dry runs: same interface, writes nothing."""

    def __init__(self, session_id: str = "-") -> None:  # noqa: D107
        self.path = Path(os.devnull)
        self.session_id = session_id
        self._lock = threading.Lock()

    def emit(self, event: str, **fields: Any) -> dict[str, Any]:
        return {"ts": time.time(), "session": self.session_id, "event": event, **fields}

    def read(self) -> list[dict[str, Any]]:
        return []
