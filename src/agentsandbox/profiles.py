"""Capability profiles: declare once, issue many.

A profile is a list of capability specs, none of which contain a real
credential — each one names a secret reference that already lives in the
macOS Keychain, ``pass``, an env var, or a file.  Profiles are safe to check
into a repo: they describe what a project needs, not how to authenticate.

Every field says both what it holds and which direction it moves - nothing
in a capability entry should require guessing:

* ``label`` - what this is called (required; there is no provider field to
  fall back on).
* ``guest_env`` - which guest environment variable receives the minted
  placeholder.
* ``injection`` - always a list of rules. One entry is the ordinary case -
  one mechanism, unconditionally - and each rule's own ``when`` (``hosts``,
  ``methods``, ``paths``) *is* the capability's grant for that mechanism;
  there is no separate top-level ``when``. More than one rule means several
  mechanisms, dispatched by which rule's ``when`` a request actually
  matches - authorization is still the union of every rule's hosts and
  methods, independently, so splitting across rules changes *where a
  mechanism attaches*, never *what is authorized*.
* ``resources``/``deny_paths``/``operations`` - capability-wide, not
  per-mechanism, so they sit directly on the entry rather than inside any
  one rule.
* ``secret`` - where the real credential comes from.

An entry declares ``secret`` (singular) in the ordinary case of one
capability, one credential.  For a body-kind request that needs several
secrets substituted at once - an OAuth password grant POSTing
client_id/client_secret/username/password as four separate
x-www-form-urlencoded fields, say - it declares ``secrets`` (plural) instead:
a name -> ``{"secret": ..., "guest_env": ...}`` mapping.  Each entry fans out
into its own independently-scoped, independently-audited capability sharing
the parent's ``injection``; unlike the top-level ``guest_env``, the one
nested inside ``secrets`` is required - a secret named only there has no
other way to reach the guest::

    {
      "label": "travis-auth",
      "injection": [{
        "when": {"hosts": ["auth.travis-ci.example"], "methods": ["POST"], "paths": ["/oauth/token"]},
        "kind": "body"
      }],
      "secrets": {
        "client_id": {
          "secret": "keychain:travis-client-id",
          "guest_env": "TRAVIS_CLIENT_ID"
        },
        "client_secret": {
          "secret": "keychain:travis-client-secret",
          "guest_env": "TRAVIS_CLIENT_SECRET"
        }
      }
    }

Example (``~/.config/asbx/profiles/oss-contributor.json``)::

    {
      "version": 1,
      "capabilities": [
        {
          "label": "github",
          "secret": "keychain:asbx-github:me",
          "injection": [{
            "when": {"hosts": ["api.github.com"], "methods": ["GET", "HEAD"], "paths": ["/repos/acme/*"]}
          }]
        },
        {
          "label": "npm",
          "secret": "keychain:asbx-npm:me",
          "injection": [{"when": {"hosts": ["registry.npmjs.org"]}}]
        },
        {
          "label": "openai",
          "secret": "keychain:asbx-openai:default",
          "injection": [{"when": {"hosts": ["api.openai.com"], "methods": ["POST"]}}]
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

from .capabilities import (
    AwsAutosignSpec,
    CapabilitySpec,
    InjectionRule,
    InjectionSpec,
    SecretRef,
    validate_guest_env_name,
)
from .config import DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_TTL_SECONDS
from .errors import CapabilityError, PolicyDenied


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


def load_profile_aws_autosign(path: Path) -> AwsAutosignSpec | None:
    """The profile's ``aws_autosign`` block, if it declared one.

    ``access_key_id`` comes back empty - a profile only ever names the real
    credential to sign with; the dummy marker is minted per session, not
    written down anywhere.
    """
    return _parse(path)[2]


def _parse(path: Path) -> tuple[list[CapabilitySpec], dict[str, str], AwsAutosignSpec | None]:
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
            specs.extend(_entry_to_specs(entry, default_store))
        except (KeyError, TypeError, ValueError, PolicyDenied) as exc:
            raise CapabilityError(f"profile {path}, entry {i}: {exc}") from exc

    # This `env` is the profile-wide block of plain, non-secret guest
    # variables - a different thing from any capability's `guest_env`, which
    # names where one specific value (a placeholder, a username) lands. Both
    # end up in the same guest environment, which is exactly why collisions
    # between them are checked below.
    raw_env = data.get("env", {})
    if not isinstance(raw_env, dict):
        raise CapabilityError(f"profile {path}: 'env' must be a mapping")

    if conflict := _guest_env_collision(raw_env, specs):
        raise CapabilityError(f"profile {path}: {conflict}")

    # injection.username.guest_env mirrors injection.username.value into the
    # guest's plain environment, so the guest's own tooling can build a
    # matching Basic-auth header without the value being written twice.
    plain_env = {str(k): str(v) for k, v in raw_env.items()}
    for spec in specs:
        for rule in spec.injection_rules:
            if rule.injection.username_guest_env:
                plain_env[rule.injection.username_guest_env] = rule.injection.username or ""

    aws_autosign = _resolve_aws_autosign(data.get("aws_autosign"), path)

    return specs, plain_env, aws_autosign


def _resolve_aws_autosign(data: Any, path: Path) -> AwsAutosignSpec | None:
    if data is None:
        return None
    if not isinstance(data, dict):
        raise CapabilityError(f"profile {path}: 'aws_autosign' must be a mapping")
    try:
        return AwsAutosignSpec(signing_secret=_resolve_secret_ref(data.get("signing_secret")))
    except (KeyError, TypeError, ValueError, PolicyDenied, CapabilityError) as exc:
        raise CapabilityError(f"profile {path}, 'aws_autosign': {exc}") from exc


def _guest_env_collision(raw_env: dict, specs: list[CapabilitySpec]) -> str | None:
    """Two different sources landing on the same guest environment variable
    name is never useful - one would silently overwrite the other, whether
    it's the profile's own `env` block, a capability's `guest_env`, or a
    `username.guest_env`. Returns an error message naming the conflict, or
    None if there is none.
    """
    seen: dict[str, str] = {str(k): "the profile's env block" for k in raw_env}
    for spec in specs:
        names = [(spec.guest_env, f"the guest_env for {spec.label!r}")]
        names += [
            (rule.injection.username_guest_env, f"the username.guest_env for {spec.label!r}")
            for rule in spec.injection_rules
            if rule.injection.username_guest_env
        ]
        for name, source in names:
            if not name:
                continue
            if name in seen:
                return f"{source} and {seen[name]} both target guest env var {name!r}"
            seen[name] = source
    return None


def _entry_to_specs(entry: dict[str, Any], default_store: str = "") -> list[CapabilitySpec]:
    """One profile entry, one or many specs.

    Most entries declare a single ``secret`` and become one spec, as always.
    An entry can instead declare ``secrets`` - a name -> {secret, guest_env}
    mapping - when one request needs several credentials substituted at once
    (an OAuth password grant POSTing client_id/client_secret/username/password
    as four separate x-www-form-urlencoded fields, say). Each key fans out
    into its own independently-scoped, independently-audited spec sharing the
    entry's ``when``/``ttl``/``injection``, rather than a new "bundle" concept
    with its own trust boundary.
    """
    if "secret" in entry and "secrets" in entry:
        raise CapabilityError("a capability must declare either 'secret' or 'secrets', not both")
    if "secrets" in entry:
        return _entry_to_specs_multi(entry, default_store)
    return [_entry_to_spec(entry, default_store)]


def _entry_to_spec(entry: dict[str, Any], default_store: str = "") -> CapabilitySpec:
    secret = _resolve_secret_ref(entry.get("secret"))
    if default_store and not secret.store:
        secret.store = default_store

    injection_rules = _resolve_injection_rules(entry.get("injection", [{}]))

    label = str(entry.get("label", ""))
    if not label:
        raise CapabilityError("a capability must have a label")

    hosts, methods, path_globs = _scope_from_injection_rules(injection_rules)
    # Capability-wide, not per-mechanism, so they live directly on the
    # entry rather than inside any one injection rule's `when`.
    resources = _as_list(entry.get("resources", []))
    deny_path_globs = _as_list(entry.get("deny_paths", []))
    operations = _as_list(entry.get("operations", []))

    guest_env = str(entry.get("guest_env", ""))
    if guest_env:
        validate_guest_env_name(guest_env, where="guest_env")

    return CapabilitySpec(
        hosts=hosts,
        label=label,
        resources=resources,
        methods=methods,
        path_globs=path_globs,
        deny_path_globs=deny_path_globs,
        operations=operations,
        secret=secret,
        injection_rules=injection_rules,
        ttl_seconds=int(entry.get("ttl", DEFAULT_TTL_SECONDS)),
        max_response_bytes=int(entry.get("max_response_bytes", DEFAULT_MAX_RESPONSE_BYTES)),
        guest_env=guest_env,
    )


def _scope_from_injection_rules(
    injection_rules: list[InjectionRule],
) -> tuple[list[str], list[str], list[str]]:
    """A capability's own ``hosts``/``methods``/``paths`` - the union of
    what its injection rules declare. There is no separate top-level
    ``when``; every capability's scope comes from here.

    Authorization checks that union, not paired combinations - `hosts` and
    `methods` stay two independent lists, exactly as `check_destination`/
    `check_operation` already treat them, so a rule pairing host A with
    method X and another pairing host B with method Y does *not* refuse
    host A with method Y. Splitting hosts/methods across rules is about
    which mechanism attaches where, never about tightening what is
    authorized.

    Each rule's own `when` is a real grant here, unlike the case where a
    top-level `when` already exists and a rule only narrows *within* it
    (there, an empty axis on a rule means "no further narrowing") - so
    every rule must name its own hosts explicitly; there is nothing to
    fall back on if it doesn't.
    """
    hosts: list[str] = []
    methods: list[str] = []
    path_globs: list[str] = []
    for i, rule in enumerate(injection_rules):
        if not rule.hosts:
            raise CapabilityError(f"injection[{i}] needs its own 'when.hosts'")
        hosts += [h for h in rule.hosts if h not in hosts]
        methods += [m for m in rule.methods if m not in methods]
        path_globs += [p for p in rule.path_globs if p not in path_globs]
    return hosts, methods or ["GET"], path_globs or ["/*"]


def _resolve_injection_rules(data: Any) -> list[InjectionRule]:
    """``injection``: always a list of rules. One entry is the common case -
    one mechanism, unconditionally, matching anything already inside the
    capability's own scope. More than one means dispatch by which entry's
    own (narrower) ``when`` a request actually matches.

    Each rule's ``when`` only narrows within the capability's own
    ``hosts``/``methods``/``paths`` - it is never itself a grant, so an
    empty axis there means "no further narrowing", not "matches nothing".
    The rest of a rule's fields are exactly an ``injection`` object's own
    shape (``kind``/``header``/``template``/``username``).
    """
    if not isinstance(data, list) or not data:
        raise CapabilityError("'injection' must be a non-empty list")
    rules: list[InjectionRule] = []
    for i, rule in enumerate(data):
        if not isinstance(rule, dict):
            raise CapabilityError(f"injection[{i}] must be a mapping")
        when = rule.get("when", {})
        if not isinstance(when, dict):
            raise CapabilityError(f"injection[{i}].when must be a mapping")
        spec = _resolve_injection(rule)
        spec.validate()
        rules.append(
            InjectionRule(
                hosts=_as_list(when.get("hosts", [])),
                methods=_as_list(when.get("methods", [])),
                path_globs=_as_list(when.get("paths", [])),
                injection=spec,
            )
        )
    return rules


def _entry_to_specs_multi(entry: dict[str, Any], default_store: str = "") -> list[CapabilitySpec]:
    label = str(entry.get("label", ""))
    if not label:
        raise CapabilityError("a capability must have a label")

    injection_rules = _resolve_injection_rules(entry.get("injection", [{}]))

    hosts, methods, path_globs = _scope_from_injection_rules(injection_rules)
    resources = _as_list(entry.get("resources", []))
    deny_path_globs = _as_list(entry.get("deny_paths", []))
    operations = _as_list(entry.get("operations", []))
    ttl_seconds = int(entry.get("ttl", DEFAULT_TTL_SECONDS))
    max_response_bytes = int(entry.get("max_response_bytes", DEFAULT_MAX_RESPONSE_BYTES))

    raw_secrets = entry.get("secrets")
    if not isinstance(raw_secrets, dict) or not raw_secrets:
        raise CapabilityError("'secrets' must be a non-empty mapping")

    specs: list[CapabilitySpec] = []
    for key, item in raw_secrets.items():
        if not isinstance(item, dict):
            raise CapabilityError(
                f"secrets[{key!r}] must be a mapping with 'secret' and 'guest_env'"
            )
        secret = _resolve_secret_ref(item.get("secret"))
        if default_store and not secret.store:
            secret.store = default_store

        # Unlike the top-level `guest_env`, this one is not optional: a
        # secret named only inside `secrets` has no other way to reach the
        # guest (no "printed at issue time for manual copy" fallback makes
        # sense for one of four fields the guest's own script must already
        # reference by name).
        guest_env = str(item.get("guest_env", ""))
        if not guest_env:
            raise CapabilityError(f"secrets[{key!r}] needs a 'guest_env'")
        validate_guest_env_name(guest_env, where=f"secrets[{key!r}].guest_env")

        specs.append(
            CapabilitySpec(
                hosts=list(hosts),
                label=f"{label}: {key}",
                resources=list(resources),
                methods=list(methods),
                path_globs=list(path_globs),
                deny_path_globs=list(deny_path_globs),
                operations=list(operations),
                secret=secret,
                injection_rules=list(injection_rules),
                ttl_seconds=ttl_seconds,
                max_response_bytes=max_response_bytes,
                guest_env=guest_env,
            )
        )
    return specs


#: Which field a secret's explicit-object form names its identifier with,
#: per backend - the term each backend actually uses for it, rather than one
#: generic name stretched over all four.
_SECRET_IDENTIFIER_KEY = {
    "keychain": "service",
    "pass": "entry",
    "env": "name",
    "file": "path",
    "aws_profile": "profile",
}


def _resolve_secret_ref(value: str | dict | None) -> SecretRef:
    """``keychain:SERVICE[:ACCOUNT]``, ``pass:path/to/entry``, ``env:NAME`` or
    ``file:/path`` as a compact string; or an explicit object naming the
    field the way that backend does - see ``_SECRET_IDENTIFIER_KEY``.
    """
    if value is None:
        raise CapabilityError("a profile capability must declare a secret")
    if isinstance(value, dict):
        return _secret_ref_from_dict(value)
    backend, _, rest = str(value).partition(":")
    if backend not in _SECRET_IDENTIFIER_KEY:
        raise CapabilityError(f"unknown secret backend {backend!r}")
    service, _, account = rest.partition(":")
    if not service:
        raise CapabilityError("secret reference is missing its service/name")
    return SecretRef(backend=backend, service=service, account=account)


def _secret_ref_from_dict(data: dict) -> SecretRef:
    backend = data.get("backend", "keychain")
    key = _SECRET_IDENTIFIER_KEY.get(backend)
    if key is None:
        raise CapabilityError(f"unknown secret backend {backend!r}")
    identifier = data.get(key)
    if not identifier:
        raise CapabilityError(f"a {backend!r} secret needs {key!r}")
    return SecretRef(
        backend=backend,
        service=str(identifier),
        account=str(data.get("account", "")),
        store=str(data.get("store", "")),
    )


def _resolve_injection(data: dict) -> InjectionSpec:
    """``username`` is either a plain string, or ``{"value": ..., "guest_env":
    ...}`` when the guest's own tooling also needs it. Nested, not a second
    flat ``username_guest_env`` field, so there is nothing shaped like it to
    swap it with.
    """
    username_field = data.get("username")
    username: str | None = None
    username_guest_env: str | None = None
    if isinstance(username_field, dict):
        username = username_field.get("value")
        username_guest_env = username_field.get("guest_env")
    elif username_field is not None:
        username = str(username_field)

    if username_guest_env:
        validate_guest_env_name(username_guest_env, where="username.guest_env")

    return InjectionSpec(
        kind=data.get("kind", "bearer"),
        header=data.get("header", "Authorization"),
        template=data.get("template", "Bearer {secret}"),
        username=username,
        username_guest_env=username_guest_env,
    )


def _as_list(value: Any) -> list:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return list(value)
    raise CapabilityError(f"expected a list or string, got {type(value).__name__}")
