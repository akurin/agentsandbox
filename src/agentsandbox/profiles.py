"""Capability profiles: declare once, issue many.

A profile is a list of capability specs, none of which contain a real
credential — each one names a SecretRef (``keychain:service:account``) that
already lives in the macOS Keychain.  Profiles are safe to check into a repo:
they describe what a project needs, not how to authenticate.

Example (``~/.config/asbx/profiles/oss-contributor.json``)::

    {
      "version": 1,
      "capabilities": [
        {
          "provider": "github",
          "hosts": ["api.github.com"],
          "methods": ["GET", "HEAD"],
          "paths": ["/repos/acme/*"],
          "secret": "keychain:asbx-github:me"
        },
        {
          "provider": "npm",
          "hosts": ["registry.npmjs.org"],
          "secret": "keychain:asbx-npm:me"
        },
        {
          "provider": "openai",
          "hosts": ["api.openai.com"],
          "methods": ["POST"],
          "secret": "keychain:asbx-openai:default"
        }
      ]
    }

Then::

    asbx session start --profile oss-contributor

Issues all three capabilities in one command.  Only the placeholder strings
are shown to the guest; the real credentials live in Keychain and are fetched
by the broker, cached for the session, and cleared on teardown.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .capabilities import CapabilitySpec, InjectionSpec, SecretRef
from .errors import CapabilityError


def profile_dirs() -> list[Path]:
    """Where profile files are looked up, in priority order.

    The project-local directory wins, then the user's config, then the
    workspace's own examples so ``asbx profile list`` always has something.
    """
    dirs: list[Path] = []
    if cwd := os.getenv("ASBX_PROFILE_DIR"):
        dirs.append(Path(cwd))
    dirs.append(Path.home() / ".config" / "asbx" / "profiles")
    dirs.append(Path(__file__).with_name("_profiles"))
    return dirs


def resolve_profile(name: str) -> Path:
    """Find the first profile file matching ``name`` in the search path."""
    for directory in profile_dirs():
        candidate = directory / f"{name}.json"
        if candidate.exists():
            return candidate
    searched = [str(d) for d in profile_dirs()]
    raise CapabilityError(
        f"no profile named {name!r} found in {', '.join(searched)}"
    )


def list_profiles() -> dict[str, Path]:
    """Return ``{name: path}`` for every profile in the search path."""
    out: dict[str, Path] = {}
    for directory in sorted(profile_dirs()):
        if not directory.is_dir():
            continue
        for path in sorted(directory.iterdir()):
            if path.suffix == ".json":
                name = path.stem
                if name not in out:
                    out[name] = path
    return out


def load_profile(path: Path) -> list[CapabilitySpec]:
    """Parse a profile file and return its capability specs."""
    data = json.loads(path.read_text())

    if not isinstance(data, dict):
        raise CapabilityError(f"profile {path} does not contain a mapping")

    version = data.get("version", 1)
    if version != 1:
        raise CapabilityError(f"unsupported profile version {version!r} in {path}")

    entries = data.get("capabilities", data.get("capability", []))
    if isinstance(entries, dict):
        entries = [entries]
    if not isinstance(entries, list):
        raise CapabilityError(f"profile {path}: 'capabilities' must be a list")

    specs: list[CapabilitySpec] = []
    for i, entry in enumerate(entries):
        try:
            specs.append(_entry_to_spec(entry))
        except (KeyError, TypeError, ValueError) as exc:
            raise CapabilityError(f"profile {path}, entry {i}: {exc}") from exc
    return specs


def _entry_to_spec(entry: dict[str, Any]) -> CapabilitySpec:
    secret = _resolve_secret_ref(entry.get("secret"))
    injection = InjectionSpec.from_dict(entry.get("injection", {}))

    return CapabilitySpec(
        provider=entry["provider"],
        account=str(entry.get("account", "")),
        hosts=_as_list(entry["hosts"]),
        resources=_as_list(entry.get("resources", [])),
        methods=_as_list(entry.get("methods", ["GET"])),
        path_globs=_as_list(entry.get("paths", ["/*"])),
        operations=_as_list(entry.get("operations", [])),
        secret=secret,
        injection=injection,
        ttl_seconds=int(entry.get("ttl", 3600)),
        max_requests=int(entry.get("max_requests", 100)),
        max_response_bytes=int(entry.get("max_response_bytes", 8 * 1024 * 1024)),
        max_total_bytes=int(entry.get("max_total_bytes", 0)),
        approval_required_methods=entry.get("approve_methods"),
        label=str(entry.get("label", "")),
        env_var=str(entry.get("env", "")),
    )


def _resolve_secret_ref(value: str | dict | None) -> SecretRef:
    """``keychain:SERVICE[:ACCOUNT]``, ``env:NAME`` or ``file:/path``."""
    if value is None:
        raise CapabilityError("a profile capability must declare a secret")
    if isinstance(value, dict):
        return SecretRef.from_dict(value)
    backend, _, rest = str(value).partition(":")
    if backend not in ("keychain", "env", "file"):
        raise CapabilityError(f"unknown secret backend {backend!r}")
    service, _, account = rest.partition(":")
    if not service:
        raise CapabilityError("secret reference is missing its service/name")
    return SecretRef(backend=backend, service=service, account=account)


def _as_list(value: Any) -> list:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return list(value)
    raise CapabilityError(f"expected a list or string, got {type(value).__name__}")
