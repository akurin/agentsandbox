"""``asbx`` - the operator's interface to the sandbox.

Everything a human does happens here, on the trusted side: starting sessions,
minting capabilities, answering approval prompts, reviewing and applying the
agent's changes.  The guest has no channel to any of it.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import signal
import sys
import time
from pathlib import Path

from .audit import AuditLog
from .broker.approvals import FileApprovalGate
from .broker.core import BrokerRequest
from .broker.server import UnixBrokerClient, read_token
from .capabilities import CapabilitySpec, CapabilityStore, InjectionSpec, SecretRef
from .config import SessionPaths
from .errors import SandboxError
from .keychain import KeychainProvider
from .manager import SessionManager, check_environment, stop_session_by_id
from .session import STATE_STOPPED, Session, Share, list_sessions, resolve_session_id
from .vm.vfkit import VmConfig

EXIT_USAGE = 2
EXIT_DENIED = 3


# ---------------------------------------------------------------------------
# helpers


def _resolve_session(session_id: str | None) -> Session:
    return Session.load(resolve_session_id(session_id))


def _print(data) -> None:
    if isinstance(data, (dict, list)):
        print(json.dumps(data, indent=2, default=str))
    else:
        print(data)


def _parse_share(value: str) -> Share:
    """``/path/to/dir:ro`` or ``/path/to/dir:rw`` (read-only is the default)."""
    path, _, mode = value.rpartition(":")
    if not path:  # no colon at all
        path, mode = value, "ro"
    if mode not in ("ro", "rw"):
        raise argparse.ArgumentTypeError(f"share mode must be ro or rw, got {mode!r}")
    resolved = Path(path).expanduser().resolve()
    if not resolved.is_dir():
        raise argparse.ArgumentTypeError(f"{resolved} is not a directory")
    tag = resolved.name.replace(" ", "_")[:32] or "share"
    return Share(path=str(resolved), tag=tag, read_only=(mode == "ro"))


def _parse_forward(value: str) -> tuple[int, int]:
    """``3000`` or ``8080:3000`` -> ``(host_port, guest_port)``.

    Same shape as ``docker -p`` and ``kubectl port-forward``: the host side
    comes first when both are given.
    """
    host_str, colon, guest_str = value.partition(":")
    try:
        if colon:
            # A colon means both sides were intended; "3000:" is a typo, not
            # a request to use 3000 twice.
            host_port, guest_port = int(host_str), int(guest_str)
        else:
            host_port = guest_port = int(host_str)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"expected PORT or HOST:GUEST, got {value!r}"
        ) from None
    for port in (host_port, guest_port):
        if not 1 <= port <= 65535:
            raise argparse.ArgumentTypeError(f"port out of range: {port}")
    return host_port, guest_port


def _parse_secret_ref(value: str) -> SecretRef:
    """``keychain:SERVICE[:ACCOUNT]``, ``env:NAME`` or ``file:/path``."""
    backend, _, rest = value.partition(":")
    if backend not in ("keychain", "env", "file"):
        raise argparse.ArgumentTypeError(f"unknown secret backend {backend!r}")
    service, _, account = rest.partition(":")
    if not service:
        raise argparse.ArgumentTypeError("secret reference is missing its service/name")
    return SecretRef(backend=backend, service=service, account=account)


# ---------------------------------------------------------------------------
# session


def cmd_env_start(args: argparse.Namespace) -> int:
    """Boot an environment: fresh identity and capabilities, existing disk."""
    from .env import Environment

    env = Environment.load(args.name)
    if args.fresh and env.has_disk:
        env.remove_disk()
        print(f"reset {env.name}'s disk")

    # Everything the environment holds becomes this run's session, except the
    # things that must be new every time: keys, CA, capabilities.
    args.allow = env.allow_hosts
    args.project = env.project_path or None
    args.mount_path = env.project_mount
    args.share = list(env.shares)
    args.profile = env.profile or None
    args.approvals = env.approval_mode
    args.cpus = env.cpus
    args.memory = env.memory_mib
    args.label = env.name
    args.purge_on_stop = False

    env.last_started = time.time()
    env.save()
    return _start_session(args, env=env)


def cmd_session_start(args: argparse.Namespace) -> int:
    return _start_session(args, env=None)


def _start_session(args: argparse.Namespace, env=None) -> int:
    problems = check_environment() if args.vm else []
    if problems and args.vm:
        for problem in problems:
            print(f"!! {problem}", file=sys.stderr)
        print("\nStart without a guest using --no-vm, or fix the above.", file=sys.stderr)
        return EXIT_USAGE

    manager = SessionManager.create(
        allow_hosts=args.allow,
        project=Path(args.project) if args.project else None,
        project_mount=args.mount_path or "",
        label=args.label,
        approval_mode=args.approvals,
        shares=args.share or [],
        env_name=env.name if env else "",
    )
    session = manager.session
    if env:
        print(f"starting {env.name} (session {session.session_id})")
        print(f"  disk       {env.disk_path}" + ("" if env.has_disk else " (building from golden)"))
    else:
        print(f"session {session.session_id} created")
    if session.policy.allow_hosts == ["*"]:
        print("  any public host is reachable (restrict with --allow HOST)")
    else:
        print(f"  allowed hosts: {', '.join(session.policy.allow_hosts)}")
    for share in session.shares:
        if share.tag == "project":
            continue  # printed below, with its mount point
        mode = "read-only" if share.read_only else "read-write"
        print(f"  share      {share.path} -> guest:/mnt/{share.tag} ({mode})")

    # Capabilities are minted before the guest boots so their placeholders can
    # be delivered as environment in cloud-init, rather than pasted by hand.
    capability_env: dict[str, str] = {}
    if args.profile:
        from .profiles import load_profile, resolve_profile

        for spec in load_profile(resolve_profile(args.profile)):
            token, cap = manager.issue_capability(spec)
            label = spec.label or spec.provider
            print(f"  cap {cap.cap_id:<18} {label} ({', '.join(spec.methods)} {', '.join(spec.hosts)})")
            if spec.env_var:
                capability_env[spec.env_var] = token
                print(f"    guest env: ${spec.env_var}")
            else:
                print(f"    placeholder: {token}  (add \"env\" to the profile to inject it)")

    vm_config = VmConfig(
        cpus=args.cpus,
        memory_mib=args.memory,
        shares=list(session.shares),
        console="stdio" if args.console else "log",
        netcheck=args.netcheck,
        capability_env=capability_env,
        # An environment boots its own disk and keeps it; an anonymous session
        # gets a throwaway clone.
        disk_override=env.disk_path if env else None,
        efi_override=env.efi_store if env else None,
        persist_disk=bool(env),
    )
    dev_targets = dict(pair.split(":", 1) for pair in args.dev_target) if args.dev_target else {}
    dev_targets = {int(k): int(v) for k, v in dev_targets.items()}

    try:
        manager.start(
            with_vm=args.vm,
            vm_config=vm_config,
            forward_ports=args.forward or [],
            dev_targets=dev_targets,
            web=args.mitmweb,
            web_port=args.web_port,
        )
    except SandboxError as exc:
        print(f"!! {exc}", file=sys.stderr)
        manager.stop(purge=True)
        return 1

    print(f"  wireguard  {session.wg_listen_host}:{session.wg_listen_port}")
    print(f"  ca         {session.paths.ca_cert}")
    print(f"  broker     {session.paths.broker_socket}")
    if session.project_path:
        mount = session.project_mount or session.project_path
        print(f"  project    {session.project_path} -> guest:{mount} (read-write)")
    for port, info in session.forwards.items():
        print(f"  forward    guest:{port} -> {info['url']}")
    if manager.mitm is not None and manager.mitm.web:
        print(f"  mitmweb    {manager.mitm.web_url}")
    if not args.vm:
        print("\nNo guest started (--no-vm). Point a WireGuard peer at the endpoint above:")
        print(f"  {session.paths.guest_wireguard_conf}")

    stop = {"requested": False}

    def _handle(signum, frame):  # noqa: ANN001, ARG001
        stop["requested"] = True

    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)

    print("\nsession running - Ctrl-C or `asbx session stop` to tear it down")
    try:
        while not stop["requested"]:
            if manager.vm is not None and not manager.vm.is_running():
                # Say *why*. Without --console vfkit's output goes to a log,
                # and "guest exited" on its own is useless.
                print("guest exited; shutting the session down", file=sys.stderr)
                log = manager.vm.vm_dir / "vfkit.log"
                if log.exists() and (tail := log.read_text(errors="replace").strip()):
                    print("\n--- vfkit.log (last 15 lines) ---", file=sys.stderr)
                    for line in tail.splitlines()[-15:]:
                        print(f"  {line}", file=sys.stderr)
                    print(f"\nFull log: {log}", file=sys.stderr)
                    print(f"More context: asbx --session {session.session_id} diag", file=sys.stderr)
                break
            time.sleep(0.5)
    finally:
        manager.stop(purge=args.purge_on_stop)
        print(f"session {session.session_id} stopped")
    return 0


def cmd_session_list(args: argparse.Namespace) -> int:
    sessions = list_sessions()
    if not sessions:
        print("no sessions")
        return 0

    stopped = 0
    for session in sessions:
        view = session.public_view()
        age = _human_age(view["age_s"])
        if session.state == STATE_STOPPED:
            stopped += 1
        detail = session.label or session.project_path or ""
        print(f"{view['session']}  {view['state']:<8} {age:>6}  {detail}")

    if stopped:
        print(
            f"\n{stopped} stopped session(s) kept for audit - they cannot be resumed "
            "(the\nguest disk is deleted and every capability revoked on teardown). "
            "Read one with\n`asbx --session <id> diag`, or clear them with "
            "`asbx session prune`."
        )
    return 0


def _human_age(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


def cmd_session_prune(args: argparse.Namespace) -> int:
    """Delete stopped sessions' leftover state."""
    from .session import purge_session_dir

    victims = [s for s in list_sessions() if s.state == STATE_STOPPED]
    if args.older_than:
        cutoff = time.time() - args.older_than * 86400
        victims = [s for s in victims if s.created_at < cutoff]

    if not victims:
        print("nothing to prune")
        return 0

    for session in victims:
        if args.dry_run:
            print(f"would remove {session.session_id}")
            continue
        purge_session_dir(session.session_id)
        print(f"removed {session.session_id}")

    if args.dry_run:
        print(f"\n{len(victims)} session(s); re-run without --dry-run to delete")
    return 0


def cmd_session_status(args: argparse.Namespace) -> int:
    session = _resolve_session(args.session)
    manager = SessionManager(session)
    _print(manager.status())
    return 0


def cmd_session_stop(args: argparse.Namespace) -> int:
    session = _resolve_session(args.session)
    if session.supervisor_pid and session.supervisor_pid != os.getpid():
        # Let the process that owns the sockets do the teardown.
        try:
            os.kill(session.supervisor_pid, signal.SIGTERM)
            print(f"asked session {session.session_id} to stop")
            return 0
        except ProcessLookupError:
            pass  # supervisor is gone; clean up from here
    stop_session_by_id(session.session_id, purge=args.purge)
    print(f"session {session.session_id} stopped")
    return 0


# ---------------------------------------------------------------------------
# capabilities


def cmd_cap_issue(args: argparse.Namespace) -> int:
    session = _resolve_session(args.session)
    manager = SessionManager(session)
    spec = CapabilitySpec(
        provider=args.provider,
        account=args.account,
        hosts=args.host,
        resources=args.resource or [],
        methods=[m.upper() for m in (args.method or ["GET", "HEAD"])],
        path_globs=args.path or ["/*"],
        operations=args.operation or [],
        secret=args.secret,
        injection=InjectionSpec(
            kind=args.injection,
            header=args.header,
            template=args.template,
            username=args.username,
        ),
        ttl_seconds=args.ttl,
        max_requests=args.max_requests,
        max_response_bytes=args.max_response_bytes,
        approval_required_methods=args.approve_methods,
        label=args.label,
    )
    token, cap = manager.issue_capability(spec)

    # Say which session this landed in. It is resolved implicitly when only one
    # is running, and "it worked but where?" is a fair thing to wonder.
    where = session.label or session.project_path or "no label"
    print(f"capability {cap.cap_id} issued for {spec.provider}")
    print(f"  in session {session.session_id} ({where})")
    print(f"  expires in {args.ttl}s, and is revoked when that session stops")

    print("\nPlaceholder (shown exactly once):\n")
    print(f"  {token}\n")
    print("Inside the guest:")
    print(f'  curl -H "Authorization: Bearer {token}" https://{spec.hosts[0]}/...')
    print(
        "\nThis is the manual path - the placeholder dies with the session and has "
        "to be pasted by hand.\nFor anything you use repeatedly, declare it in a "
        "profile instead and it arrives as an\nenvironment variable in every session:\n"
    )
    print("  ~/.config/asbx/profiles/my-project.json")
    print(
        "  {\n"
        '    "version": 1,\n'
        '    "capabilities": [\n'
        "      {\n"
        f'        "provider": "{spec.provider}", "env": "{spec.provider.upper()}_TOKEN",\n'
        f'        "hosts": {json.dumps(spec.hosts)},\n'
        f'        "methods": {json.dumps(spec.methods)}, "paths": {json.dumps(spec.path_globs)},\n'
        f'        "secret": "{spec.secret.backend}:{spec.secret.service}'
        f'{":" + spec.secret.account if spec.secret.account else ""}"\n'
        "      }\n"
        "    ]\n"
        "  }\n"
    )
    print("  asbx session start --profile my-project")
    return 0


def cmd_cap_try(args: argparse.Namespace) -> int:
    """Send one request through the broker exactly as the addon would.

    Two modes, both useful when something returns 403 and you need to know
    which layer said no:

    * default - build the broker core in this process. Tests the capability,
      the Keychain lookup, credential injection and the upstream call, with no
      VM and no running session required.
    * ``--via-broker`` - go through the unix socket to the *running* broker,
      which additionally tests the transport and the session's own policy.
    """
    import urllib.parse

    session = _resolve_session(args.session)
    parsed = urllib.parse.urlsplit(args.url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        print(f"!! not a usable url: {args.url}", file=sys.stderr)
        return EXIT_USAGE

    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query

    headers = [("Accept", "*/*"), ("User-Agent", "asbx-cap-try/1")]
    for raw in args.header or []:
        name, _, value = raw.partition(":")
        if not value:
            print(f"!! header must be 'Name: value', got {raw!r}", file=sys.stderr)
            return EXIT_USAGE
        headers.append((name.strip(), value.strip()))

    body = args.data.encode() if args.data else b""
    request = BrokerRequest(
        session_id=session.session_id,
        capability=args.capability,
        method=args.method.upper(),
        scheme=parsed.scheme,
        host=parsed.hostname,
        port=parsed.port or (443 if parsed.scheme == "https" else 80),
        target=target,
        headers=headers,
        body=body,
        operation=args.operation,
        flow_id="cap-try",
    )

    if args.via_broker:
        client = UnixBrokerClient(
            session.paths.broker_socket, read_token(session.paths.broker_token)
        )
        response = client.call(request)
        route = "running broker"
    else:
        response = SessionManager(session).build_broker().handle(request)
        route = "in-process broker core"

    marker = "allow" if response.decision == "allow" else "DENY "
    print(f"{marker}  {response.status_code}  {len(response.body)} bytes  via {route}")
    if response.reason:
        print(f"       reason: {response.reason}")
    if response.cap_id:
        print(f"       capability: {response.cap_id}")
    if args.show_body:
        print("\n" + response.body.decode("utf-8", "replace")[: args.max_body])
    return 0 if response.decision == "allow" else EXIT_DENIED


def cmd_cap_list(args: argparse.Namespace) -> int:
    """List capabilities. Without a session, list every session's.

    Listing is read-only and unambiguous across sessions, so it does not need
    a target the way issuing and revoking do.
    """
    if args.session or os.environ.get("ASBX_SESSION"):
        sessions = [_resolve_session(args.session)]
    else:
        sessions = list_sessions()
        if not sessions:
            print("no sessions")
            return 0

    out = []
    for session in sessions:
        store = CapabilityStore(session.paths.capabilities, session.session_id)
        for cap in store.list():
            view = cap.public_view()
            view["session_state"] = session.state
            out.append(view)

    if not out:
        print(f"no capabilities in {len(sessions)} session(s)")
        return 0
    _print(out)
    return 0


def cmd_cap_revoke(args: argparse.Namespace) -> int:
    session = _resolve_session(args.session)
    store = CapabilityStore(session.paths.capabilities, session.session_id)
    if args.cap_id == "all":
        count = store.revoke_all()
        AuditLog(session.paths.audit_log, session.session_id).emit(
            "capability.revoked_all", count=count
        )
        print(f"revoked {count} capabilities")
        return 0
    if store.revoke(args.cap_id):
        AuditLog(session.paths.audit_log, session.session_id).emit(
            "capability.revoked", cap_id=args.cap_id
        )
        print(f"revoked {args.cap_id}")
        return 0
    print(f"no such capability: {args.cap_id}", file=sys.stderr)
    return 1


# ---------------------------------------------------------------------------
# secrets and approvals


def cmd_secret_set(args: argparse.Namespace) -> int:
    secret = os.environ.get("ASBX_SECRET") or getpass.getpass("secret: ")
    if not secret:
        print("empty secret, nothing stored", file=sys.stderr)
        return EXIT_USAGE
    KeychainProvider().store(
        SecretRef(backend="keychain", service=args.service, account=args.account), secret
    )
    print(f"stored keychain item service={args.service} account={args.account or args.service}")
    return 0


def cmd_approvals(args: argparse.Namespace) -> int:
    session = _resolve_session(args.session)
    gate = FileApprovalGate(session.paths.root / "approvals")
    pending = gate.list_pending()
    if not pending:
        print("no pending approvals")
        return 0
    for item in pending:
        age = int(time.time() - item["created_at"])
        print(f"{item['request_id']}  {item['method']} {item['url']}  ({age}s ago)")
        print(f"    capability {item['cap_id']} provider {item['provider']}")
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    session = _resolve_session(args.session)
    gate = FileApprovalGate(session.paths.root / "approvals")
    gate.answer(args.request_id, approved=not args.deny, note=args.note)
    print(f"{'denied' if args.deny else 'approved'} {args.request_id}")
    return 0



# ---------------------------------------------------------------------------
# misc


def cmd_audit(args: argparse.Namespace) -> int:
    session = _resolve_session(args.session)
    log = AuditLog(session.paths.audit_log, session.session_id)
    records = log.read()
    for record in records[-args.tail :]:
        stamp = time.strftime("%H:%M:%S", time.localtime(record["ts"]))
        detail = {
            k: v for k, v in record.items() if k not in ("ts", "session", "event")
        }
        print(f"{stamp} {record['event']:<28} {json.dumps(detail, default=str)}")
    return 0


def cmd_guest_config(args: argparse.Namespace) -> int:
    session = _resolve_session(args.session)
    paths: SessionPaths = session.paths
    if args.what == "wireguard":
        print(paths.guest_wireguard_conf.read_text())
    elif args.what == "ca":
        print(paths.ca_cert.read_text() if paths.ca_cert.exists() else "", end="")
    else:
        _print(
            {
                "wireguard_conf": str(paths.guest_wireguard_conf),
                "ca_cert": str(paths.ca_cert),
                "cloud_init": str(paths.vm / "cloud-init" / "user-data"),
            }
        )
    return 0


def cmd_profile_list(args: argparse.Namespace) -> int:
    from .profiles import list_profiles

    profiles = list_profiles()
    if not profiles:
        print("no profiles found")
        return 0
    for name, path in sorted(profiles.items()):
        print(f"{name:<24} {path}")
    return 0


def cmd_profile_show(args: argparse.Namespace) -> int:

    from .profiles import load_profile, resolve_profile

    path = resolve_profile(args.name)
    specs = load_profile(path)
    print(f"# {path}")
    for spec in specs:
        print(f"  - provider: {spec.provider}")
        print(f"    hosts: [{', '.join(spec.hosts)}]")
        print(f"    methods: [{', '.join(spec.methods)}]")
        print(f"    paths: [{', '.join(spec.path_globs)}]")
        print(f"    secret: {spec.secret.backend}:{spec.secret.service}"
              f"{':' + spec.secret.account if spec.secret.account else ''}")
        if spec.resources:
            print(f"    resources: [{', '.join(spec.resources)}]")
        if spec.label:
            print(f"    label: {spec.label}")
        print()
    return 0


def cmd_diag(args: argparse.Namespace) -> int:
    """Everything needed to explain a misbehaving session, in one output.

    Ordered by how often it is the answer: what the gateway saw, what the guest
    said on its way up, then the proxy and the audit trail.
    """
    session = _resolve_session(args.session)
    paths = session.paths
    manager = SessionManager(session)
    status = manager.status()

    def section(title: str) -> None:
        print(f"\n=== {title} " + "=" * max(0, 60 - len(title)))

    section("session")
    _print(
        {
            k: status[k]
            for k in ("session", "state", "allow_hosts", "forwards", "approval_mode", "wireguard")
            if k in status
        }
    )
    print(
        f"proxy_running={status.get('proxy_running')} vm_running={status.get('vm_running')} "
        f"supervisor_running={status.get('supervisor_running')}"
    )

    section("l2 gateway (guest -> host frames)")
    gateway = status.get("gateway") or {}
    if gateway:
        _print(gateway)
        if not gateway.get("frames_in"):
            print("!! no frames at all: the guest NIC is not talking to our socket")
        elif not gateway.get("relayed"):
            print("!! frames arrive but none are WireGuard to the endpoint - see drops_by_reason")
    else:
        print("no gateway stats (session not running, or started with --no-vm)")

    section("guest endpoint config")
    if paths.guest_wireguard_conf.exists():
        for line in paths.guest_wireguard_conf.read_text().splitlines():
            if line.startswith(("Endpoint", "Address", "DNS", "AllowedIPs", "MTU")):
                print("  " + line)

    for name, path in (
        ("guest bootstrap", paths.guest_logs / "bootstrap.log"),
        ("guest netcheck", paths.guest_logs / "netcheck.log"),
        ("mitmproxy", paths.root / "mitmproxy.log"),
        ("vfkit", paths.vm / "vfkit.log"),
    ):
        section(f"{name} ({path.name})")
        if not path.exists():
            print(f"(missing: {path})")
            continue
        text = path.read_text(errors="replace").strip()
        print("\n".join(text.splitlines()[-args.tail :]) if text else "(empty)")

    section(f"audit (last {args.tail})")
    for record in AuditLog(paths.audit_log, session.session_id).read()[-args.tail :]:
        detail = {k: v for k, v in record.items() if k not in ("ts", "session", "event")}
        print(
            f"{time.strftime('%H:%M:%S', time.localtime(record['ts']))} "
            f"{record['event']:<26} {json.dumps(detail, default=str)}"
        )
    return 0


# ---------------------------------------------------------------------------
# environments


def cmd_env_create(args: argparse.Namespace) -> int:
    """Define an environment. Nothing boots until `asbx start`."""
    from .env import Environment, validate_name

    name = validate_name(args.name)
    if Environment.exists(name) and not args.force:
        print(f"!! environment {name!r} already exists (--force to redefine)", file=sys.stderr)
        return EXIT_USAGE

    project = Path(args.project).expanduser().resolve() if args.project else None
    if project and not project.is_dir():
        print(f"!! {project} is not a directory", file=sys.stderr)
        return EXIT_USAGE

    env = Environment(
        name=name,
        project_path=str(project) if project else "",
        project_mount=args.mount_path or "",
        profile=args.profile or "",
        allow_hosts=list(args.allow or ["*"]),
        shares=args.share or [],
        approval_mode=args.approvals,
        cpus=args.cpus,
        memory_mib=args.memory,
    )
    env.save()
    print(f"environment {name} created")
    if project:
        print(f"  project  {project} -> guest:{env.project_mount or project}")
    if env.profile:
        print(f"  profile  {env.profile}")
    print(f"  disk     {env.disk_path} (built on first start)")
    print(f"\nStart it with:  asbx start {name}")
    return 0


def cmd_env_list(args: argparse.Namespace) -> int:
    from .env import list_environments
    from .session import STATE_RUNNING

    envs = list_environments()
    if not envs:
        print("no environments; create one with `asbx create NAME --project DIR`")
        return 0

    running = {s.env_name for s in list_sessions() if s.state == STATE_RUNNING and s.env_name}
    for env in envs:
        state = "running" if env.name in running else ("stopped" if env.has_disk else "not built")
        size = f"{env.disk_size() / 1e9:.1f}G" if env.has_disk else "-"
        print(f"{env.name:<20} {state:<10} {size:>6}  {env.project_path}")
    return 0


def cmd_env_inspect(args: argparse.Namespace) -> int:
    from .env import Environment

    _print(Environment.load(args.name).public_view())
    return 0


def cmd_env_rm(args: argparse.Namespace) -> int:
    from .env import Environment

    env = Environment.load(args.name)
    size = f" ({env.disk_size() / 1e9:.1f}G)" if env.has_disk else ""
    env.delete(keep_disk=args.keep_disk)
    print(f"removed environment {env.name}{'' if args.keep_disk else size}")
    return 0


def cmd_env_stop(args: argparse.Namespace) -> int:
    """Stop the run belonging to an environment (or the only running one)."""
    from .session import STATE_RUNNING

    running = [s for s in list_sessions() if s.state == STATE_RUNNING]
    if args.name:
        running = [s for s in running if s.env_name == args.name]
        if not running:
            print(f"!! {args.name} is not running", file=sys.stderr)
            return EXIT_USAGE
    elif not running:
        print("nothing is running")
        return 0
    elif len(running) > 1:
        listed = "\n".join(f"  {s.env_name or s.session_id}" for s in running)
        print(f"!! several are running - name one:\n{listed}", file=sys.stderr)
        return EXIT_USAGE

    session = running[0]
    if session.supervisor_pid and session.supervisor_pid != os.getpid():
        try:
            os.kill(session.supervisor_pid, signal.SIGTERM)
            print(f"asked {session.env_name or session.session_id} to stop")
            return 0
        except ProcessLookupError:
            pass
    stop_session_by_id(session.session_id, purge=args.purge)
    print(f"stopped {session.env_name or session.session_id}")
    return 0


def cmd_env_reset(args: argparse.Namespace) -> int:
    """Throw the guest filesystem away; the next start rebuilds from golden."""
    from .env import Environment

    env = Environment.load(args.name)
    if not env.has_disk:
        print(f"{env.name} has no disk yet; nothing to reset")
        return 0
    env.remove_disk()
    print(f"reset {env.name}; the next start rebuilds it from the golden image")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    problems = check_environment()
    if not problems:
        print("all good: mitmproxy, vfkit and a golden image are present")
        return 0
    for problem in problems:
        print(f"!! {problem}")
    return 1


# ---------------------------------------------------------------------------
# parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="asbx", description=__doc__)
    parser.add_argument("--session", help="session id (default: the newest running session)")
    sub = parser.add_subparsers(dest="command", required=True)

    # -- environments (the everyday path) -----------------------------------
    create = sub.add_parser("create", help="define an environment (does not boot it)")
    create.add_argument("name")
    create.add_argument("--project", help="host directory to mount in the guest")
    create.add_argument("--mount-path", help="where it mounts inside (default: same as host)")
    create.add_argument("--profile", help="capability profile to issue on every start")
    create.add_argument("--allow", action="append", default=[], metavar="HOST",
                        help="restrict egress to these hosts (default: all public)")
    create.add_argument("--share", action="append", type=_parse_share, metavar="PATH:ro|rw",
                        help="extra host directory at /mnt/<name>")
    create.add_argument("--approvals", choices=["deny", "file", "allow"], default="deny")
    create.add_argument("--cpus", type=int, default=2)
    create.add_argument("--memory", type=int, default=2048, help="guest RAM in MiB")
    create.add_argument("--force", action="store_true", help="redefine an existing environment")
    create.set_defaults(func=cmd_env_create)

    start = sub.add_parser("start", help="boot an environment")
    start.add_argument("name")
    start.add_argument("--fresh", action="store_true", help="discard the disk and rebuild it")
    start.add_argument("--forward", action="append", type=_parse_forward, default=[],
                       metavar="[HOST:]GUEST", help="forward a guest port to localhost")
    start.add_argument("--dev-target", action="append", default=[], metavar="GUESTPORT:HOSTPORT",
                       help=argparse.SUPPRESS)
    start.add_argument("--mitmweb", action="store_true", help="live traffic inspector on loopback")
    start.add_argument("--web-port", type=int, default=0)
    start.add_argument("--console", action="store_true", default=True,
                       help="attach the guest console to this terminal (default)")
    start.add_argument("--no-console", dest="console", action="store_false")
    start.add_argument("--netcheck", choices=["halt", "warn"], default="halt")
    start.set_defaults(func=cmd_env_start, vm=True)

    ls = sub.add_parser("ls", help="list environments")
    ls.set_defaults(func=cmd_env_list)

    inspect = sub.add_parser("inspect", help="show an environment's configuration")
    inspect.add_argument("name")
    inspect.set_defaults(func=cmd_env_inspect)

    rm = sub.add_parser("rm", help="delete an environment and its disk")
    rm.add_argument("name")
    rm.add_argument("--keep-disk", action="store_true")
    rm.set_defaults(func=cmd_env_rm)

    stop_env = sub.add_parser("stop", help="stop a running environment")
    stop_env.add_argument("name", nargs="?", help="environment name (default: the only running one)")
    stop_env.add_argument("--purge", action="store_true", help="also erase the run's audit trail")
    stop_env.set_defaults(func=cmd_env_stop)

    reset = sub.add_parser("reset", help="discard an environment's disk, keeping its config")
    reset.add_argument("name")
    reset.set_defaults(func=cmd_env_reset)

    # -- session ------------------------------------------------------------
    session_parser = sub.add_parser("session", help="session lifecycle")
    session_sub = session_parser.add_subparsers(dest="subcommand", required=True)

    start = session_sub.add_parser("start", help="create and run a session")
    start.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="HOST",
        help="restrict the guest to only these hosts (default: all public hosts; repeatable)",
    )
    start.add_argument("--project", help="host directory to mount in the guest")
    start.add_argument("--mount-path", help="where --project mounts inside the guest (default: same as host)")
    start.add_argument("--profile", help="issue every capability in this profile on start")
    start.add_argument("--label", default="", help="human label for this session")
    start.add_argument(
        "--approvals",
        choices=["deny", "file", "allow"],
        default="deny",
        help="how mutating operations are approved (default: deny everything)",
    )
    start.add_argument(
        "--share",
        action="append",
        type=_parse_share,
        metavar="PATH:ro|rw",
        help="mount an extra host directory at /mnt/<name> (default read-only)",
    )
    start.add_argument(
        "--forward",
        action="append",
        type=_parse_forward,
        default=[],
        metavar="[HOST:]GUEST",
        help="forward a guest port to localhost, e.g. 3000 or 8080:3000 (repeatable)",
    )
    start.add_argument(
        "--dev-target",
        action="append",
        default=[],
        metavar="GUESTPORT:HOSTPORT",
        help="with --no-vm, point a forward at a host port instead of the guest",
    )
    start.add_argument("--cpus", type=int, default=2)
    start.add_argument("--memory", type=int, default=2048, help="guest RAM in MiB")
    start.add_argument("--no-vm", dest="vm", action="store_false", help="host side only")
    start.add_argument(
        "--netcheck",
        choices=["halt", "warn"],
        default="halt",
        help="what the guest does if it is not fail-closed (default: power off)",
    )
    start.add_argument(
        "--mitmweb",
        action="store_true",
        help="expose the live mitmproxy web UI on loopback",
    )
    start.add_argument(
        "--web-port",
        type=int,
        default=0,
        help="fixed port for --mitmweb (default: random)",
    )
    start.add_argument(
        "--console",
        action="store_true",
        help="attach the guest console to this terminal (autologin as `agent`)",
    )
    start.add_argument(
        "--purge-on-stop",
        action="store_true",
        help="erase all session state on shutdown, not just the disk",
    )
    start.set_defaults(func=cmd_session_start, vm=True, console=False)

    session_sub.add_parser("list", help="list sessions").set_defaults(func=cmd_session_list)

    status = session_sub.add_parser("status", help="show one session")
    status.set_defaults(func=cmd_session_status)

    prune = session_sub.add_parser("prune", help="delete stopped sessions' leftover state")
    prune.add_argument("--older-than", type=int, metavar="DAYS", help="only those older than N days")
    prune.add_argument("--dry-run", action="store_true")
    prune.set_defaults(func=cmd_session_prune)

    stop = session_sub.add_parser("stop", help="tear a session down")
    stop.add_argument("--purge", action="store_true", help="also erase session state")
    stop.set_defaults(func=cmd_session_stop)

    # -- capabilities -------------------------------------------------------
    cap = sub.add_parser("cap", help="capability management")
    cap_sub = cap.add_subparsers(dest="subcommand", required=True)

    issue = cap_sub.add_parser("issue", help="mint a capability placeholder")
    issue.add_argument("--provider", required=True, help="e.g. github, openai, aws")
    issue.add_argument("--account", default="", help="which account at that provider")
    issue.add_argument(
        "--host", action="append", required=True, help="hostname the capability covers (repeatable)"
    )
    issue.add_argument("--resource", action="append", help="e.g. repo:acme/api (repeatable)")
    issue.add_argument("--method", action="append", help="permitted HTTP method (repeatable)")
    issue.add_argument("--path", action="append", help="permitted path glob (repeatable)")
    issue.add_argument("--operation", action="append", help="permitted semantic operation")
    issue.add_argument(
        "--secret",
        type=_parse_secret_ref,
        required=True,
        metavar="keychain:SERVICE[:ACCOUNT]",
        help="where the real credential lives",
    )
    issue.add_argument("--injection", choices=["bearer", "header", "basic"], default="bearer")
    issue.add_argument("--header", default="Authorization", help="header name for --injection header")
    issue.add_argument("--template", default="Bearer {secret}", help="value template, must contain {secret}")
    issue.add_argument("--username", help="username for --injection basic")
    issue.add_argument("--ttl", type=int, default=3600, help="lifetime in seconds")
    issue.add_argument("--max-requests", type=int, default=100)
    issue.add_argument("--max-response-bytes", type=int, default=8 * 1024 * 1024)
    issue.add_argument(
        "--approve-methods",
        nargs="*",
        help="methods needing operator approval (default: POST PUT PATCH DELETE)",
    )
    issue.add_argument("--label", default="")
    issue.set_defaults(func=cmd_cap_issue)

    cap_sub.add_parser("list", help="list capabilities").set_defaults(func=cmd_cap_list)

    try_cmd = cap_sub.add_parser(
        "try", help="send one request through the broker, as the guest would"
    )
    try_cmd.add_argument("capability", help="the cap_v1_... placeholder")
    try_cmd.add_argument("--url", required=True, help="full https URL to request")
    try_cmd.add_argument("--method", default="GET")
    try_cmd.add_argument("--header", action="append", metavar="NAME: VALUE")
    try_cmd.add_argument("--data", help="request body")
    try_cmd.add_argument("--operation", help="semantic operation name, if the capability binds one")
    try_cmd.add_argument(
        "--via-broker",
        action="store_true",
        help="go through the running broker's socket instead of an in-process core",
    )
    try_cmd.add_argument("--show-body", action="store_true")
    try_cmd.add_argument("--max-body", type=int, default=2000)
    try_cmd.set_defaults(func=cmd_cap_try)

    revoke = cap_sub.add_parser("revoke", help="revoke one capability, or 'all'")
    revoke.add_argument("cap_id")
    revoke.set_defaults(func=cmd_cap_revoke)

    # -- secrets ------------------------------------------------------------
    secret = sub.add_parser("secret", help="credentials in the macOS keychain")
    secret_sub = secret.add_subparsers(dest="subcommand", required=True)
    secret_set = secret_sub.add_parser("set", help="store a credential (prompts, never echoes)")
    secret_set.add_argument("--service", required=True)
    secret_set.add_argument("--account", default="")
    secret_set.set_defaults(func=cmd_secret_set)

    # -- approvals ----------------------------------------------------------
    sub.add_parser("approvals", help="list pending approvals").set_defaults(func=cmd_approvals)
    approve = sub.add_parser("approve", help="answer a pending approval")
    approve.add_argument("request_id")
    approve.add_argument("--deny", action="store_true")
    approve.add_argument("--note", default="")
    approve.set_defaults(func=cmd_approve)



    # -- profiles -----------------------------------------------------------
    profile = sub.add_parser("profile", help="capability profiles")
    profile_sub = profile.add_subparsers(dest="subcommand", required=True)
    profile_list = profile_sub.add_parser("list", help="list available profiles")
    profile_list.set_defaults(func=cmd_profile_list)
    profile_show = profile_sub.add_parser("show", help="show one profile's contents")
    profile_show.add_argument("name")
    profile_show.set_defaults(func=cmd_profile_show)

    # -- misc ---------------------------------------------------------------
    audit = sub.add_parser("audit", help="show the session audit log")
    audit.add_argument("--tail", type=int, default=50)
    audit.set_defaults(func=cmd_audit)

    guest = sub.add_parser("guest", help="files the guest needs")
    guest.add_argument("what", nargs="?", choices=["paths", "wireguard", "ca"], default="paths")
    guest.set_defaults(func=cmd_guest_config)

    diag = sub.add_parser("diag", help="one-shot diagnostics for a misbehaving session")
    diag.add_argument("--tail", type=int, default=25, help="lines per log section")
    diag.set_defaults(func=cmd_diag)

    sub.add_parser("doctor", help="check the host prerequisites").set_defaults(func=cmd_doctor)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except SandboxError as exc:
        print(f"!! {exc}", file=sys.stderr)
        return EXIT_DENIED
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
