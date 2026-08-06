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
          "label": "github",
          "hosts": ["api.github.com"],
          "methods": ["GET", "HEAD"],
          "paths": ["/repos/acme/*"],
          "secret": "keychain:asbx-github:me"
        },
        {
          "label": "npm",
          "hosts": ["registry.npmjs.org"],
          "secret": "keychain:asbx-npm:me"
        },
        {
          "label": "openai",
          "hosts": ["api.openai.com"],
          "methods": ["POST"],
          "secret": "keychain:asbx-openai:default"
        }
      ]
    }

Then::

    asbx box create neo --profile oss-contributor && asbx box start neo

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
from .config import DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_TTL_SECONDS
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
    return _parse(path)[0]


def load_profile_env(path: Path) -> dict[str, str]:
    """Non-secret box the profile wants in the guest.

    A base URL or a username is configuration, not a credential - it has no
    business going through the broker, and the agent needs it to build the
    request at all.
    """
    return _parse(path)[1]


def _parse(path: Path) -> tuple[list[CapabilitySpec], dict[str, str]]:
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

    # A profile for one project usually points at one store; let it say so
    # once instead of on every capability.
    default_store = str(data.get("pass_store", ""))

    specs: list[CapabilitySpec] = []
    for i, entry in enumerate(entries):
        try:
            specs.append(_entry_to_spec(entry, default_store))
        except (KeyError, TypeError, ValueError) as exc:
            raise CapabilityError(f"profile {path}, entry {i}: {exc}") from exc

    plain_env = data.get("env", {})
    if not isinstance(plain_env, dict):
        raise CapabilityError(f"profile {path}: 'env' must be a mapping")
    return specs, {str(k): str(v) for k, v in plain_env.items()}


def _entry_to_spec(entry: dict[str, Any], default_store: str = "") -> CapabilitySpec:
    secret = _resolve_secret_ref(entry.get("secret"))
    if default_store and not secret.store:
        secret.store = default_store
    injection = InjectionSpec.from_dict(entry.get("injection", {}))

    label = str(entry.get("label", ""))
    if not label:
        raise CapabilityError("a capability must have a label")

    return CapabilitySpec(
        hosts=_as_list(entry["hosts"]),
        label=label,
        account=str(entry.get("account", "")),
        resources=_as_list(entry.get("resources", [])),
        methods=_as_list(entry.get("methods", ["GET"])),
        path_globs=_as_list(entry.get("paths", ["/*"])),
        deny_path_globs=_as_list(entry.get("deny_paths", [])),
        operations=_as_list(entry.get("operations", [])),
        secret=secret,
        injection=injection,
        ttl_seconds=int(entry.get("ttl", DEFAULT_TTL_SECONDS)),
        max_response_bytes=int(entry.get("max_response_bytes", DEFAULT_MAX_RESPONSE_BYTES)),
        env_var=str(entry.get("env", "")),
    )


def _resolve_secret_ref(value: str | dict | None) -> SecretRef:
    """``keychain:SERVICE[:ACCOUNT]``, ``pass:path/to/entry``, ``env:NAME`` or ``file:/path``."""
    if value is None:
        raise CapabilityError("a profile capability must declare a secret")
    if isinstance(value, dict):
        return SecretRef.from_dict(value)
    backend, _, rest = str(value).partition(":")
    if backend not in ("keychain", "pass", "env", "file"):
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
