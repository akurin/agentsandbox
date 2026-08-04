"""Error types shared across the host-side components.

Everything that can reject a request carries a machine-readable ``reason`` so
that audit records stay stable and greppable, and a ``message`` that is safe to
show to the guest (it must never contain a credential or a capability).
"""

from __future__ import annotations


class SandboxError(Exception):
    """Base class for all sandbox errors."""

    reason = "sandbox_error"


class PolicyDenied(SandboxError):
    """A request was refused by policy. Always fail closed with this."""

    def __init__(self, reason: str, message: str | None = None) -> None:
        self.reason = reason
        self.message = message or reason.replace("_", " ")
        super().__init__(self.message)


class CapabilityError(SandboxError):
    reason = "capability_error"


class SessionError(SandboxError):
    reason = "session_error"


class BrokerError(SandboxError):
    reason = "broker_error"


class UpstreamError(SandboxError):
    reason = "upstream_error"
