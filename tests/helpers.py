"""Test doubles shared by several modules."""

from __future__ import annotations

from agentsandbox.broker.core import BrokerRequest
from agentsandbox.broker.upstream import UpstreamResponse


class RecordingExecutor:
    """Stands in for the real upstream executor.

    Records what the broker tried to send (so tests can assert on credential
    injection) and returns a scripted response.
    """

    def __init__(self, response: UpstreamResponse | None = None) -> None:
        self.response = response or UpstreamResponse(
            status_code=200,
            headers=[("Content-Type", "application/json")],
            body=b'{"ok": true}',
        )
        self.calls: list[dict] = []

    def execute(self, dest, method, target, headers, body, credential_headers, max_bytes):
        self.calls.append(
            {
                "dest": dest,
                "method": method,
                "target": target,
                "headers": list(headers),
                "body": body,
                "credential_headers": list(credential_headers),
                "max_bytes": max_bytes,
            }
        )
        return self.response

    @property
    def last(self) -> dict:
        assert self.calls, "executor was never called"
        return self.calls[-1]


def make_request(token: str, **overrides) -> BrokerRequest:
    fields = {
        "session_id": "test-session",
        "capability": token,
        "method": "GET",
        "scheme": "https",
        "host": "api.github.com",
        "port": 443,
        "target": "/repos/acme/api/issues",
        "headers": [("Accept", "application/json"), ("Authorization", f"Bearer {token}")],
        "body": b"",
    }
    fields.update(overrides)
    return BrokerRequest(**fields)
