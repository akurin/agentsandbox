"""Credential sources for the broker.

The default backend is the macOS Keychain, read through ``/usr/bin/security``
so that the OS - not this process - owns the storage and the ACL prompt.  Two
other backends exist for tests and for credentials that legitimately live in a
file (``env`` and ``file``); both are refused for anything but a session the
operator explicitly configured that way.

Nothing in this module logs a secret, and every value fetched is registered
with the audit redactor so that if it later appears in a header, a body, or an
exception string, it is scrubbed before it can reach a log line.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .audit import redactor
from .capabilities import SecretRef
from .errors import BrokerError

SECURITY_BIN = "/usr/bin/security"


class SecretProvider:
    """Resolves a :class:`SecretRef` to a live credential."""

    def fetch(self, ref: SecretRef) -> str:  # pragma: no cover - interface
        raise NotImplementedError


@dataclass
class KeychainProvider(SecretProvider):
    """Reads generic passwords from the login keychain.

    The value is returned as text.  A JSON value is treated as an OAuth token
    bundle (see :class:`OAuthProvider`), which is how refreshable credentials
    are stored.
    """

    keychain: str | None = None
    timeout: float = 15.0

    def fetch(self, ref: SecretRef) -> str:
        if not ref.service:
            raise BrokerError("secret ref has no keychain service")
        argv = [
            SECURITY_BIN,
            "find-generic-password",
            "-s",
            ref.service,
            "-w",
        ]
        if ref.account:
            argv[2:2] = ["-a", ref.account]
        if self.keychain:
            argv.append(self.keychain)
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=self.timeout, check=False
            )
        except FileNotFoundError as exc:  # not macOS
            raise BrokerError("keychain backend unavailable on this platform") from exc
        except subprocess.TimeoutExpired as exc:
            raise BrokerError("keychain access timed out (unlock prompt?)") from exc
        if proc.returncode != 0:
            # stderr can contain the item name but never the password.
            raise BrokerError(f"keychain item not found for service={ref.service!r}")
        secret = proc.stdout.rstrip("\n")
        if not secret:
            raise BrokerError("keychain item is empty")
        redactor.register_secret(secret)
        return secret

    def store(self, ref: SecretRef, secret: str) -> None:
        """Write (or replace) an item. Used by ``asbx secret set``."""
        argv = [
            SECURITY_BIN,
            "add-generic-password",
            "-U",
            "-s",
            ref.service,
            "-a",
            ref.account or ref.service,
            "-w",
            secret,
            "-T",
            "",  # no application is pre-authorised to read it
        ]
        if self.keychain:
            argv.append(self.keychain)
        proc = subprocess.run(argv, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            raise BrokerError("failed to store keychain item")
        redactor.register_secret(secret)


@dataclass
class EnvProvider(SecretProvider):
    """Reads from the broker process environment. Development convenience."""

    def fetch(self, ref: SecretRef) -> str:
        name = ref.service or ref.account
        value = os.environ.get(name)
        if not value:
            raise BrokerError(f"environment secret {name!r} is not set")
        redactor.register_secret(value)
        return value


@dataclass
class FileProvider(SecretProvider):
    """Reads a 0600 file. Refuses anything more permissive."""

    def fetch(self, ref: SecretRef) -> str:
        path = Path(ref.service).expanduser()
        if not path.is_file():
            raise BrokerError("secret file does not exist")
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            raise BrokerError(f"secret file {path} is group/world readable ({mode:o})")
        value = path.read_text().strip()
        if not value:
            raise BrokerError("secret file is empty")
        redactor.register_secret(value)
        return value


#: How long a fetched credential stays in memory before the broker fetches it
#: again. The Keychain access prompt appears once then is silent for this long.
#: Set ``ASBX_SECRET_CACHE_TTL=0`` to disable caching entirely (a prompt on
#: every brokered request).
DEFAULT_CACHE_TTL = float(os.environ.get("ASBX_SECRET_CACHE_TTL", 900))


class SecretResolver:
    """Dispatches on ``SecretRef.backend`` and refreshes OAuth bundles.

    Fetched credentials are cached in memory so that one session means one
    Keychain prompt, not one per request. The cache lives only in the broker
    process, is dropped when the session stops, and every value in it is
    registered with the audit redactor regardless of age.
    """

    def __init__(
        self,
        keychain: KeychainProvider | None = None,
        providers: dict[str, SecretProvider] | None = None,
        cache_ttl: float = DEFAULT_CACHE_TTL,
    ) -> None:
        self.keychain = keychain or KeychainProvider()
        self.providers: dict[str, SecretProvider] = providers or {
            "keychain": self.keychain,
            "env": EnvProvider(),
            "file": FileProvider(),
        }
        self.cache_ttl = cache_ttl
        self._cache: dict[tuple[str, str, str], tuple[str, float]] = {}

    def clear_cache(self) -> None:
        """Forget every cached credential. Called when a session stops."""
        self._cache.clear()

    def fetch(self, ref: SecretRef) -> str:
        provider = self.providers.get(ref.backend)
        if provider is None:
            raise BrokerError(f"unknown secret backend {ref.backend!r}")

        cache_key = (ref.backend, ref.service, ref.account)
        cached = self._cache.get(cache_key)
        if cached is not None:
            raw, expires_at = cached
            if time.time() < expires_at:
                redactor.register_secret(raw)
                token, _ = _resolve_token(raw, provider, ref)
                return token
            del self._cache[cache_key]

        raw = provider.fetch(ref)
        if self.cache_ttl > 0:
            self._cache[cache_key] = (raw, time.time() + self.cache_ttl)

        token, _ = _resolve_token(raw, provider, ref)
        return token


def _resolve_token(raw: str, provider: SecretProvider, ref: SecretRef) -> tuple[str, bool]:
    """Parse an OAuth bundle or return the raw value if it is a plain token."""
    bundle = _parse_oauth_bundle(raw)
    if bundle is None:
        redactor.register_secret(raw)
        return raw, False
    token, refreshed = refresh_oauth_if_needed(bundle)
    if refreshed and isinstance(provider, KeychainProvider):
        provider.store(ref, json.dumps(bundle))
    redactor.register_secret(token)
    return token, refreshed


def _parse_oauth_bundle(raw: str) -> dict | None:
    """An OAuth bundle is a JSON object with at least an ``access_token``."""
    stripped = raw.lstrip()
    if not stripped.startswith("{"):
        return None
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    if isinstance(data, dict) and "access_token" in data:
        return data
    return None


def refresh_oauth_if_needed(bundle: dict, *, skew: float = 60.0) -> tuple[str, bool]:
    """Return ``(access_token, was_refreshed)``, refreshing in place if expired.

    Only the refresh grant is implemented, and only against the token endpoint
    recorded in the bundle - the guest has no way to influence any of it.
    """
    expires_at = float(bundle.get("expires_at") or 0)
    token = str(bundle.get("access_token") or "")
    if not expires_at or time.time() + skew < expires_at:
        return token, False

    refresh_token = bundle.get("refresh_token")
    token_url = bundle.get("token_url")
    if not refresh_token or not token_url:
        raise BrokerError("credential expired and cannot be refreshed")

    form = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": bundle.get("client_id", ""),
    }
    if bundle.get("client_secret"):
        form["client_secret"] = bundle["client_secret"]
    if bundle.get("scope"):
        form["scope"] = bundle["scope"]

    parsed = urllib.parse.urlparse(token_url)
    if parsed.scheme != "https":
        raise BrokerError("refusing to refresh a token over plaintext http")

    request = urllib.request.Request(
        token_url,
        data=urllib.parse.urlencode(form).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as resp:
            payload = json.loads(resp.read(1_000_000).decode())
    except Exception as exc:  # noqa: BLE001 - surface as a broker error, no detail leak
        raise BrokerError(f"oauth refresh failed: {type(exc).__name__}") from exc

    new_token = payload.get("access_token")
    if not new_token:
        raise BrokerError("oauth refresh returned no access_token")
    bundle["access_token"] = new_token
    if payload.get("refresh_token"):
        bundle["refresh_token"] = payload["refresh_token"]
    if payload.get("expires_in"):
        bundle["expires_at"] = time.time() + float(payload["expires_in"])
    redactor.register_secret(new_token)
    return new_token, True


class StaticResolver(SecretResolver):
    """Test double: a dict of ``service`` -> secret, no OS involvement."""

    def __init__(self, secrets: dict[str, str]) -> None:
        self._secrets = dict(secrets)
        for value in secrets.values():
            redactor.register_secret(value)

    def fetch(self, ref: SecretRef) -> str:
        key = ref.service or ref.account
        if key not in self._secrets:
            raise BrokerError(f"no test secret for {key!r}")
        return self._secrets[key]
