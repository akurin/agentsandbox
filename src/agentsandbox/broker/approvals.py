"""Human-in-the-loop approval for operations that change something.

The spec requires confirmation for writes, deployment, messaging and
destructive actions.  The default gate is :class:`DenyAll` - a session that
was never given an approval channel simply cannot mutate anything.

:class:`FileApprovalGate` is the real one: it drops a pending request in the
session directory, waits, and lets the operator answer with
``asbx approve <id>`` / ``asbx deny <id>`` from a trusted terminal.  The guest
cannot see or write that directory.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..config import ensure_private_dir, write_private_file


@dataclass
class ApprovalRequest:
    session_id: str
    cap_id: str
    provider: str
    method: str
    url: str
    reason: str = ""
    body_preview: str = ""
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)

    def summary(self) -> str:
        return f"{self.method} {self.url} (capability {self.cap_id}, provider {self.provider})"


class ApprovalGate:
    """Interface. ``decide`` returns True to allow the operation."""

    def decide(self, request: ApprovalRequest) -> bool:  # pragma: no cover - interface
        raise NotImplementedError


class DenyAll(ApprovalGate):
    """Default. No approval channel configured means no mutating operations."""

    def decide(self, request: ApprovalRequest) -> bool:
        return False


class AllowAll(ApprovalGate):
    """Only for tests and explicitly unattended sessions."""

    def decide(self, request: ApprovalRequest) -> bool:
        return True


class FileApprovalGate(ApprovalGate):
    """Pending requests as files; the operator answers out of band.

    Layout under the session directory::

        approvals/pending/<id>.json    written by the broker
        approvals/decided/<id>.json    written by `asbx approve|deny`

    A request that is not answered within ``timeout`` is denied, so a wedged
    operator never turns into an open gate.
    """

    def __init__(self, root: Path, timeout: float = 120.0, poll: float = 0.25) -> None:
        self.root = root
        self.pending = ensure_private_dir(root / "pending")
        self.decided = ensure_private_dir(root / "decided")
        self.timeout = timeout
        self.poll = poll

    def decide(self, request: ApprovalRequest) -> bool:
        path = self.pending / f"{request.request_id}.json"
        write_private_file(path, json.dumps(request.to_dict(), indent=2))
        answer_path = self.decided / f"{request.request_id}.json"
        deadline = time.monotonic() + self.timeout
        try:
            while time.monotonic() < deadline:
                if answer_path.exists():
                    try:
                        answer = json.loads(answer_path.read_text())
                    except json.JSONDecodeError:
                        return False
                    return bool(answer.get("approved"))
                time.sleep(self.poll)
            return False
        finally:
            path.unlink(missing_ok=True)

    # -- operator side ------------------------------------------------------

    def list_pending(self) -> list[dict]:
        out = []
        for path in sorted(self.pending.glob("*.json")):
            try:
                out.append(json.loads(path.read_text()))
            except json.JSONDecodeError:
                continue
        return out

    def answer(self, request_id: str, approved: bool, note: str = "") -> None:
        write_private_file(
            self.decided / f"{request_id}.json",
            json.dumps(
                {
                    "request_id": request_id,
                    "approved": approved,
                    "note": note,
                    "decided_at": time.time(),
                }
            ),
        )
