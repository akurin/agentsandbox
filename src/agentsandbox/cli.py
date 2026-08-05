"""``asbx`` - the operator's interface to the sandbox.

Everything a human does happens here, on the trusted side: starting boxes,
minting capabilities, reviewing and applying the agent's changes.  The guest
has no channel to any of it.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import shlex
import signal
import sys
import time
from pathlib import Path

from .audit import AuditLog
from .broker.core import BrokerRequest
from .broker.server import UnixBrokerClient, read_token
from .capabilities import CapabilitySpec, CapabilityStore, InjectionSpec, SecretRef
from .config import DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_TTL_SECONDS
from .errors import SandboxError
from .keychain import KeychainProvider
from .manager import SessionManager, check_host, stop_session_by_id
from .session import STATE_STOPPED, Session, Share, list_sessions, resolve_session_id
from .vm.vfkit import DEFAULT_IMAGE, VmConfig, default_golden_image, resolve_image

EXIT_USAGE = 2
EXIT_DENIED = 3


# ---------------------------------------------------------------------------
# helpers


def _resolve_session(target: str | None) -> Session:
    """Which session a command acts on.

    ``target`` may be a box name (what every `box`, `cap` and `secret`
    subcommand actually passes - the bare positional on `box` commands,
    ``--box`` everywhere else) or a session id. A box can have at most one
    running session (`cmd_box_start` already refuses to start a second), so
    naming the box is never ambiguous where naming the session id would have
    been; it just fails with "not running" instead of guessing.

    A bare session id still works, and still has to for a stopped session:
    `asbx box diag ID` is the only way to look at one after its box has moved
    on to a different run.
    """
    from .box import Box
    from .errors import SessionError

    if target and Box.exists(target):
        session = _running_session_for(target)
        if session is None:
            raise SessionError(f"{target} is not running; start it with `asbx box start`")
        return session
    return Session.load(resolve_session_id(target))


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
    """``keychain:SERVICE[:ACCOUNT]``, ``pass:path/to/entry``, ``env:NAME`` or ``file:/path``."""
    backend, _, rest = value.partition(":")
    if backend not in ("keychain", "pass", "env", "file"):
        raise argparse.ArgumentTypeError(f"unknown secret backend {backend!r}")
    service, _, account = rest.partition(":")
    if not service:
        raise argparse.ArgumentTypeError("secret reference is missing its service/name")
    return SecretRef(backend=backend, service=service, account=account)


# ---------------------------------------------------------------------------
# box lifecycle


def cmd_box_start(args: argparse.Namespace) -> int:
    """Boot a box: fresh identity and capabilities, existing disk."""
    from .box import Box

    box = Box.load(args.name)

    # One guest per box: they share a disk, and a second vfkit opening
    # it fails deep inside Virtualization.framework with "the storage device
    # attachment is invalid", which says nothing about the real cause.
    if existing := _running_session_for(box.name):
        print(f"!! {box.name} is already running (session {existing.session_id})", file=sys.stderr)
        print(f"   asbx box shell {box.name}    open a shell in it", file=sys.stderr)
        print(f"   asbx box stop {box.name}     stop it first to restart", file=sys.stderr)
        return EXIT_USAGE

    # Before the fork, so a missing image is an error in this terminal rather
    # than three identical lines in a log file the operator has to be told
    # about. An image can be deleted after the box was created.
    if not resolve_image(box.image).exists():
        print(f"!! {box.name} needs image {box.image!r}, which is not built", file=sys.stderr)
        print("   asbx image ls                           what is built", file=sys.stderr)
        print(f"   asbx box set {box.name} --image NAME    point it at one of those", file=sys.stderr)
        return EXIT_USAGE

    if args.fresh and box.has_disk:
        box.remove_disk()
        print(f"reset {box.name}'s disk")

    # Everything the box holds becomes this run's session, except the
    # things that must be new every time: keys, CA, capabilities.
    args.allow = box.allow_hosts
    args.project = box.project_path or None
    args.mount_path = box.project_mount
    args.share = list(box.shares)
    args.profile = box.profile or None
    args.cpus = box.cpus
    args.memory = box.memory_mib
    args.label = box.name
    args.purge_on_stop = False

    box.last_started = time.time()
    box.save()

    if args.attach:
        # Foreground: this terminal owns the guest, and Ctrl-C stops it. Useful
        # when the guest is broken enough that ssh never comes up.
        args.console = True
        return _start_session(args, box=box)

    # Unlock every secret the profile needs while we still have a terminal,
    # and carry the loaded resolver across the fork. The supervisor has no
    # terminal, so a pinentry fired from there has nowhere to draw itself.
    resolver = None
    if box.profile:
        resolver, problem = _warm_secrets(box.profile)
        if problem:
            print(f"!! {problem}", file=sys.stderr)
            return EXIT_DENIED

    # Detached, like `podman start`: the supervisor outlives this terminal, so
    # `asbx box shell` from anywhere keeps working and closing the window is safe.
    args.console = False
    from .daemon import StartupFailed, spawn_supervisor

    try:
        spawn_supervisor(
            lambda: _start_session(args, box=box, resolver=resolver),
            log_path=box_supervisor_log(box),
        )
    except StartupFailed as exc:
        print(f"!! {box.name} failed to start: {exc}", file=sys.stderr)
        print(f"   log: {box_supervisor_log(box)}", file=sys.stderr)
        return 1

    _report_started(box)
    return 0


def _warm_secrets(profile_name: str):
    """Unlock every secret a profile needs, here, where a prompt can be seen.

    Returns ``(resolver, error)``. The resolver comes back holding the
    plaintext, and the caller hands it to the session *before* the supervisor
    forks - so the cache is inherited and the detached process never has to
    read a secret with no terminal to prompt in. That is what makes one unlock
    last for days.

    An unreadable secret stops the start with an explanation, rather than
    surfacing hours later as a brokered request that mysteriously 401s.
    """
    from .errors import SandboxError
    from .keychain import SecretResolver
    from .profiles import load_profile, resolve_profile

    resolver = SecretResolver()
    seen: set[tuple[str, str, str, str]] = set()
    for spec in load_profile(resolve_profile(profile_name)):
        ref = spec.secret
        key = (ref.backend, ref.service, ref.account, ref.store)
        if key in seen:
            continue
        seen.add(key)
        try:
            resolver.fetch(ref)
        except SandboxError as exc:
            where = f"{ref.backend}:{ref.service}" + (f":{ref.account}" if ref.account else "")
            return resolver, f"cannot read the secret for {spec.provider} ({where}): {exc}"

    # From here there is no going back to a terminal, so stop expiring them.
    resolver.hold_for_session()
    return resolver, None


def _running_session_for(box_name: str) -> Session | None:
    """The live session for a box, if there is one.

    A session file can say RUNNING after a crash, so the supervisor's pid is
    what decides - otherwise a killed run would block every future start.
    """
    from .manager import _is_alive
    from .session import STATE_RUNNING, STATE_STOPPED

    for session in list_sessions():
        if session.box_name != box_name or session.state != STATE_RUNNING:
            continue
        if _is_alive(session.supervisor_pid) or _is_alive(session.vm_pid):
            return session
        # Stale: the supervisor died without tidying up. Record that rather
        # than leaving a corpse that blocks the box forever.
        session.state = STATE_STOPPED
        session.save()
    return None


def box_supervisor_log(box) -> Path:
    return box.ssh_dir.parent / f"{box.name}.log"


def _report_started(box) -> None:
    """Summarise a detached box, since its own output went to a log."""
    from .session import STATE_RUNNING

    session = next(
        (s for s in list_sessions() if s.box_name == box.name and s.state == STATE_RUNNING),
        None,
    )
    print(f"{box.name} started")
    if session is None:
        return
    print(f"  session    {session.session_id}")

    # Capabilities are issued inside the supervisor, whose output goes to a
    # log. Say what the guest actually got, or a profile that silently issued
    # nothing looks identical to one that worked.
    caps = CapabilityStore(session.paths.capabilities, session.session_id).list()
    for cap in caps:
        print(f"  cap        {cap.cap_id}  {cap.provider} ({', '.join(cap.hosts)})")
    if box.profile and not caps:
        print(f"  !! profile {box.profile!r} issued no capabilities - see {box_supervisor_log(box)}")

    for port, info in session.forwards.items():
        print(f"  forward    guest:{port} -> {info['url']}")
    print(f"\n  asbx box shell {box.name}      open a shell (as many as you like)")
    print(f"  asbx box stop {box.name}       shut it down")


def _ssh_vm_config(box, session) -> dict:
    """SSH key material for the guest, or nothing for an anonymous session."""
    if box is None:
        return {}
    from .box import SshIdentity

    identity = SshIdentity(box.ssh_dir)
    if not identity.exists:
        identity.generate(box.name)
    return {
        "ssh_host_key": identity.host_key.read_text(),
        "ssh_host_pub": identity.host_key.with_suffix(".pub").read_text(),
        "ssh_authorized_key": identity.client_key.with_suffix(".pub").read_text(),
        "ssh_socket": session.paths.run / "ssh.sock",
    }


def _start_session(args: argparse.Namespace, box=None, resolver=None) -> int:
    problems = check_host() if args.vm else []
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
        shares=args.share or [],
        box_name=box.name if box else "",
    )
    session = manager.session
    if box:
        print(f"starting {box.name} (session {session.session_id})")
        print(f"  disk       {box.disk_path}" + ("" if box.has_disk else " (building from golden)"))
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
    # be delivered as environment variables in cloud-init, rather than pasted by hand.
    capability_env: dict[str, str] = {}
    if args.profile:
        from .profiles import load_profile, load_profile_env, resolve_profile

        profile_path = resolve_profile(args.profile)
        capability_env.update(load_profile_env(profile_path))
        for name in sorted(load_profile_env(profile_path)):
            print(f"  box {name}")
        for spec in load_profile(profile_path):
            token, cap = manager.issue_capability(spec)
            label = spec.label or spec.provider
            print(f"  cap {cap.cap_id:<18} {label} ({', '.join(spec.methods)} {', '.join(spec.hosts)})")
            if spec.env_var:
                capability_env[spec.env_var] = token
                print(f"    guest env: ${spec.env_var}")
            else:
                print(f"    placeholder: {token}  (add \"box\" to the profile to inject it)")

    vm_config = VmConfig(
        cpus=args.cpus,
        memory_mib=args.memory,
        shares=list(session.shares),
        console="stdio" if args.console else "log",
        netcheck=args.netcheck,
        capability_env=capability_env,
        # A box boots its own disk and keeps it; an anonymous session
        # gets a throwaway clone.
        disk_override=box.disk_path if box else None,
        efi_override=box.efi_store if box else None,
        persist_disk=bool(box),
        # The box names its own base image, so `asbx box reset` rebuilds
        # from what it was created with rather than from whatever was built
        # on this host most recently.
        golden_image=resolve_image(box.image) if box else default_golden_image(),
        # sshd only exists in a box, where `asbx box shell` needs it. A
        # one-off session keeps the smaller surface of console-only access.
        **_ssh_vm_config(box, session),
    )
    dev_targets = dict(pair.split(":", 1) for pair in args.dev_target) if args.dev_target else {}
    dev_targets = {int(k): int(v) for k, v in dev_targets.items()}

    try:
        manager.start(
            with_vm=args.vm,
            vm_config=vm_config,
            forward_ports=args.forward or [],
            dev_targets=dev_targets,
            resolver=resolver,
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
    if not args.vm:
        print("\nNo guest started (--no-vm). Point a WireGuard peer at the endpoint above:")
        print(f"  {session.paths.guest_wireguard_conf}")

    _supervise(manager, purge=args.purge_on_stop)
    return 0


def _await_ssh_channel(manager, timeout: float = 20.0) -> None:
    """Block until vfkit has created the ssh socket, if there is to be one.

    Only waits when ssh was configured: a boxless session (`_start_session`
    with no box, reachable only through `SessionManager.create()` now, not
    through the CLI) has no sshd and no socket, and waiting for one would add
    twenty seconds to every such run before timing out for a file that is
    never coming.

    Not waiting for *sshd* - that is inside the guest and takes as long as the
    boot takes. `asbx box shell` retries for it.
    """
    driver = getattr(manager, "vm", None)
    socket_path = getattr(getattr(driver, "vm", None), "ssh_socket", None)
    if not socket_path:
        return
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if Path(socket_path).exists():
            return
        time.sleep(0.1)


def _supervise(manager: SessionManager, *, purge: bool = False) -> None:
    """Own the session until the guest exits or someone asks us to stop.

    This is the whole job of the supervisor process: hold the broker, the L2
    gateway and the forwards open for as long as the guest is alive, then tear
    them down in the order that revokes capabilities first.
    """
    from .daemon import signal_ready

    session = manager.session
    stop = {"requested": False}

    def _handle(signum, frame):  # noqa: ANN001, ARG001
        stop["requested"] = True

    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)

    # Do not report ready until the box is usable. `asbx box start` prints
    # "asbx box shell NAME" as the next step, and vfkit creates that socket a
    # moment after the guest process exists - so signalling here immediately
    # meant `asbx box start neo && asbx box shell neo` lost a race with its
    # own advice, and failed claiming the session predated ssh support.
    _await_ssh_channel(manager)

    # Detached: tell the CLI it can return. Foreground: a no-op.
    signal_ready()

    try:
        while not stop["requested"]:
            if manager.vm is not None and not manager.vm.is_running():
                # Say *why*. Without a console attached, vfkit's output goes to
                # a log, and "guest exited" on its own is useless.
                print("guest exited; shutting the session down", file=sys.stderr)
                log = manager.vm.vm_dir / "vfkit.log"
                if log.exists() and (tail := log.read_text(errors="replace").strip()):
                    print("\n--- vfkit.log (last 15 lines) ---", file=sys.stderr)
                    for line in tail.splitlines()[-15:]:
                        print(f"  {line}", file=sys.stderr)
                    print(f"\nFull log: {log}", file=sys.stderr)
                    print(f"More context: asbx box diag {session.session_id}", file=sys.stderr)
                break
            time.sleep(0.5)
    finally:
        manager.stop(purge=purge)
        print(f"session {session.session_id} stopped")


def cmd_system_sessions(args: argparse.Namespace) -> int:
    """Every session that ever ran, across every box (`asbx box ls` lists box
    *definitions*; this lists individual *runs* - several stopped sessions can
    belong to the same box name over its history)."""
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
            "Read one with\n`asbx box diag <id>`, or clear them with "
            "`asbx system prune`."
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


def cmd_system_prune(args: argparse.Namespace) -> int:
    """Delete stopped sessions' leftover state. Not box-scoped: sweeps every
    box's history at once, including a box since renamed or deleted."""
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


def cmd_box_status(args: argparse.Namespace) -> int:
    session = _resolve_session(args.name)
    manager = SessionManager(session)
    _print(manager.status())
    return 0


# ---------------------------------------------------------------------------
# capabilities


def cmd_cap_issue(args: argparse.Namespace) -> int:
    session = _resolve_session(args.box)
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
        max_response_bytes=args.max_response_bytes,
        label=args.label,
    )
    token, cap = manager.issue_capability(spec)

    # Say which session this landed in. It is resolved implicitly when only one
    # is running, and "it worked but where?" is a fair thing to wonder.
    where = session.label or session.project_path or "no label"
    print(f"capability {cap.cap_id} issued for {spec.provider}")
    print(f"  in session {session.session_id} ({where})")
    lifetime = f"expires in {args.ttl}s, and is" if args.ttl else "does not expire, but is"
    print(f"  {lifetime} revoked when that session stops")

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
    print("  asbx box create my-project --profile my-project && asbx box start my-project")
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

    session = _resolve_session(args.box)
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
    """List capabilities. Without --box, list every session's.

    Listing is read-only and unambiguous across sessions, so it does not need
    a target the way issuing and revoking do.
    """
    if args.box or os.environ.get("ASBX_SESSION"):
        sessions = [_resolve_session(args.box)]
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


def cmd_cap_renew(args: argparse.Namespace) -> int:
    session = _resolve_session(args.box)
    store = CapabilityStore(session.paths.capabilities, session.session_id)
    cap = store.renew(args.cap_id, ttl_seconds=args.ttl)
    if cap is None:
        print(f"no such capability: {args.cap_id}", file=sys.stderr)
        return 1

    AuditLog(session.paths.audit_log, session.session_id).emit(
        "capability.renewed", cap_id=cap.cap_id, ttl=args.ttl
    )
    print(f"renewed {cap.cap_id} ({cap.provider})")
    print(f"  expires in {args.ttl}s" if args.ttl else "  no longer expires")
    print("  takes effect on the next request; no restart needed")
    return 0


def cmd_cap_revoke(args: argparse.Namespace) -> int:
    session = _resolve_session(args.box)
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
# secrets


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


def cmd_secret_refresh(args: argparse.Namespace) -> int:
    """Pick up a rotated credential without restarting the box.

    Unlocks the store here, where you can answer the prompt, then tells the
    running broker to drop what it cached. Its next brokered request re-reads
    against a warm agent - so a credential that rotated mid-run lands without
    interrupting an agent that has been working for days.
    """
    from .broker.server import send_command
    from .box import Box

    session = _resolve_session(args.box)
    if session.box_name and Box.exists(session.box_name):
        box = Box.load(session.box_name)
        if box.profile:
            _, problem = _warm_secrets(box.profile)
            if problem:
                print(f"!! {problem}", file=sys.stderr)
                return EXIT_DENIED

    answer = send_command(
        session.paths.broker_socket, read_token(session.paths.broker_token), "refresh-secrets"
    )
    if not answer.get("ok"):
        print(f"!! {answer.get('error', 'refresh failed')}", file=sys.stderr)
        return 1
    print(f"refreshed credentials for {session.box_name or session.session_id}")
    return 0


# ---------------------------------------------------------------------------
# misc


def cmd_audit(args: argparse.Namespace) -> int:
    session = _resolve_session(args.name)
    log = AuditLog(session.paths.audit_log, session.session_id)
    records = log.read()
    for record in records[-args.tail :]:
        stamp = time.strftime("%H:%M:%S", time.localtime(record["ts"]))
        detail = {
            k: v for k, v in record.items() if k not in ("ts", "session", "event")
        }
        print(f"{stamp} {record['event']:<28} {json.dumps(detail, default=str)}")
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
    """Print what a profile resolves to, resolved rather than as written.

    Everything that changes behaviour is shown, including the parts the file
    left out - a default is still a decision, and the reason to run this is to
    find out what it will actually do. Fields that are only documentation are
    not shown at all.
    """
    from .profiles import load_profile, load_profile_env, resolve_profile

    path = resolve_profile(args.name)
    specs = load_profile(path)
    print(f"# {path}")

    if literals := load_profile_env(path):
        print("\n  guest environment (literal, not secret):")
        for name, value in sorted(literals.items()):
            print(f"    {name}={value}")

    for spec in specs:
        inject = spec.injection
        how = {
            "basic": f"basic auth as {inject.username!r}",
            "bearer": "Authorization: Bearer <secret>",
            "header": f"{inject.header}: {inject.template.replace('{secret}', '<secret>')}",
        }.get(inject.kind, inject.kind)

        print(f"\n  - provider: {spec.provider}")
        print(f"    placeholder:  ${spec.env_var}" if spec.env_var else
              "    placeholder:  (none - copy it from `asbx cap issue` by hand)")
        print(f"    secret:       {spec.secret.backend}:{spec.secret.service}"
              f"{':' + spec.secret.account if spec.secret.account else ''}")
        print(f"    attached as:  {how}")
        print(f"    hosts:        {', '.join(spec.hosts)}")
        print(f"    methods:      {', '.join(spec.methods)}")
        print(f"    paths:        {', '.join(spec.path_globs)}")
        if spec.deny_path_globs:
            print(f"    denied:       {', '.join(spec.deny_path_globs)}")
        if spec.resources:
            print(f"    resources:    {', '.join(spec.resources)}")
        print(f"    expires:      {f'{spec.ttl_seconds}s' if spec.ttl_seconds else 'never'}")
    print()
    return 0


def _diag_session(explicit: str | None) -> Session:
    """The session to explain - falling back to the most recent stopped one.

    Ordinary commands refuse when nothing is running, which is right: acting on
    a dead session is a mistake. Diagnosis is the opposite case. A guest that
    fails hard powers itself off, so by the time anyone runs `asbx box diag` there
    is nothing running *by definition* - and refusing to look is refusing
    exactly when the logs matter most.
    """
    if explicit:
        return Session.load(explicit)
    try:
        return _resolve_session(None)
    except SandboxError:
        stopped = sorted(list_sessions(), key=lambda s: s.created_at)
        if not stopped:
            raise
        newest = stopped[-1]
        print(
            f"# nothing running; showing the most recent session "
            f"({newest.session_id}, {newest.state})",
            file=sys.stderr,
        )
        return newest


def cmd_diag(args: argparse.Namespace) -> int:
    """Everything needed to explain a misbehaving session, in one output.

    Ordered by how often it is the answer: what the gateway saw, what the guest
    said on its way up, then the proxy and the audit trail.
    """
    session = _diag_session(args.name)
    paths = session.paths
    manager = SessionManager(session)
    status = manager.status()

    def section(title: str) -> None:
        print(f"\n=== {title} " + "=" * max(0, 60 - len(title)))

    section("session")
    _print(
        {
            k: status[k]
            for k in ("session", "state", "allow_hosts", "forwards", "wireguard")
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
        # The console comes first among the logs, and before the guest's own
        # files, because it is the only one that exists when the guest fails
        # early. bootstrap.log and netcheck.log are written *by* the bootstrap
        # into a virtio-fs share - if cloud-init never ran, or the share never
        # mounted, they are simply absent, and their absence is the symptom
        # rather than the explanation. The console says why.
        ("guest console", paths.vm / "console.log"),
        ("cloud-init", paths.guest_logs / "cloud-init.log"),
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
        # The console gets a longer tail than the rest: it carries an entire
        # boot, and the interesting part is rarely in the last 25 lines.
        lines = max(args.tail, 200) if path.name == "console.log" else args.tail
        print("\n".join(text.splitlines()[-lines:]) if text else "(empty)")

    section(f"audit (last {args.tail})")
    for record in AuditLog(paths.audit_log, session.session_id).read()[-args.tail :]:
        detail = {k: v for k, v in record.items() if k not in ("ts", "session", "event")}
        print(
            f"{time.strftime('%H:%M:%S', time.localtime(record['ts']))} "
            f"{record['event']:<26} {json.dumps(detail, default=str)}"
        )
    return 0


# ---------------------------------------------------------------------------
# boxes


def cmd_box_create(args: argparse.Namespace) -> int:
    """Define a box. Nothing boots until `asbx box start`."""
    from .box import Box, validate_name

    name = validate_name(args.name)
    if Box.exists(name) and not args.force:
        print(f"!! box {name!r} already exists (--force to redefine)", file=sys.stderr)
        return EXIT_USAGE

    project = Path(args.project).expanduser().resolve() if args.project else None
    if project and not project.is_dir():
        print(f"!! {project} is not a directory", file=sys.stderr)
        return EXIT_USAGE

    from .vm.vfkit import image_path, resolve_image as _resolve_image

    if not _resolve_image(args.image).exists():
        # Creating a box on an image that does not exist would look
        # fine until the first start, which fails inside vfkit.
        print(f"!! no image named {args.image!r} at {image_path(args.image)}", file=sys.stderr)
        print("   asbx image ls                       what is built", file=sys.stderr)
        print("   ASBX_DISTRO=ubuntu ./vm/build-image.sh   build another", file=sys.stderr)
        return EXIT_USAGE

    box = Box(
        name=name,
        project_path=str(project) if project else "",
        project_mount=args.mount_path or "",
        profile=args.profile or "",
        allow_hosts=list(args.allow or ["*"]),
        shares=args.share or [],
        cpus=args.cpus,
        memory_mib=args.memory,
        image=args.image,
    )
    from .box import SshIdentity

    SshIdentity(box.ssh_dir).generate(name)
    box.save()
    print(f"box {name} created")
    if project:
        print(f"  project  {project} -> guest:{box.project_mount or project}")
    if box.profile:
        print(f"  profile  {box.profile}")
    print(f"  image    {box.image}")
    print(f"  disk     {box.disk_path} (built on first start)")
    print(f"\nStart it with:  asbx box start {name}")
    return 0


def cmd_box_set(args: argparse.Namespace) -> int:
    """Change a box's hardware. The disk is untouched.

    cpus and memory are arguments to vfkit at boot, not state on the disk, so
    resizing costs nothing but a restart - which is worth saying out loud,
    because "will I lose my work?" is the obvious worry and the answer is no.
    """
    from .box import Box

    box = Box.load(args.name)
    changes = []
    if args.memory is not None:
        if args.memory < 512:
            print(f"!! {args.memory} MiB is too little to boot; 512 is the floor", file=sys.stderr)
            return EXIT_USAGE
        changes.append(f"memory  {box.memory_mib} -> {args.memory} MiB")
        box.memory_mib = args.memory
    if args.cpus is not None:
        if args.cpus < 1:
            print("!! --cpus must be at least 1", file=sys.stderr)
            return EXIT_USAGE
        changes.append(f"cpus    {box.cpus} -> {args.cpus}")
        box.cpus = args.cpus
    if args.image is not None:
        if not resolve_image(args.image).exists():
            print(f"!! no image named {args.image!r} - see `asbx image ls`", file=sys.stderr)
            return EXIT_USAGE
        changes.append(f"image   {box.image} -> {args.image}")
        box.image = args.image

    if not changes:
        print("nothing to change: pass --memory, --cpus or --image", file=sys.stderr)
        return EXIT_USAGE

    box.save()
    print(f"{box.name} updated")
    for line in changes:
        print(f"  {line}")
    print(f"  disk    {box.disk_path} (untouched)")

    if args.image is not None and box.has_disk:
        # Changing the image does not re-clone: the box already has a
        # disk, and start boots that. Saying nothing here would leave the
        # config claiming a distro the guest is not running.
        print(f"\n  the disk still holds the old image; `asbx box reset {box.name}` re-clones")

    if _running_session_for(box.name):
        # Silently writing config a running guest is not using would look like
        # it worked and change nothing.
        print(f"\n{box.name} is running with the old settings. To apply:")
        print(f"  asbx box stop {box.name} && asbx box start {box.name}")
    return 0


def cmd_box_list(args: argparse.Namespace) -> int:
    from .box import list_boxes
    from .session import STATE_RUNNING

    boxes = list_boxes()
    if not boxes:
        print("no boxes; create one with `asbx box create NAME --project DIR`")
        return 0

    running = {s.box_name for s in list_sessions() if s.state == STATE_RUNNING and s.box_name}
    for box in boxes:
        state = "running" if box.name in running else ("stopped" if box.has_disk else "not built")
        size = f"{box.disk_size() / 1e9:.1f}G" if box.has_disk else "-"
        print(f"{box.name:<20} {state:<10} {size:>6}  {box.project_path}")
    return 0


def cmd_box_inspect(args: argparse.Namespace) -> int:
    from .box import Box

    _print(Box.load(args.name).public_view())
    return 0


def cmd_box_rm(args: argparse.Namespace) -> int:
    from .box import Box

    box = Box.load(args.name)
    size = f" ({box.disk_size() / 1e9:.1f}G)" if box.has_disk else ""
    box.delete(keep_disk=args.keep_disk)
    print(f"removed box {box.name}{'' if args.keep_disk else size}")
    return 0


def cmd_shell(args: argparse.Namespace) -> int:
    """Open a shell in a running box, over ssh-on-vsock.

    Any number of these can run at once, which is the point - the console is a
    single seat, this is not.
    """
    from .box import Box, SshIdentity
    from .session import STATE_RUNNING

    box = Box.load(args.name) if args.name else None
    running = [s for s in list_sessions() if s.state == STATE_RUNNING]
    if box:
        running = [s for s in running if s.box_name == box.name]
    if not running:
        target = args.name or "anything"
        print(f"!! {target} is not running; start it with `asbx box start`", file=sys.stderr)
        return EXIT_USAGE
    if len(running) > 1:
        listed = "\n".join(f"  {s.box_name or s.session_id}" for s in running)
        print(f"!! several are running - name one:\n{listed}", file=sys.stderr)
        return EXIT_USAGE

    session = running[0]
    box = box or Box.load(session.box_name)
    identity = SshIdentity(box.ssh_dir)
    if not identity.exists:
        print(f"!! {box.name} has no ssh keys; recreate it with `asbx box create`", file=sys.stderr)
        return EXIT_USAGE

    # vfkit creates this a moment after the guest process appears. `asbx box
    # start` now waits for it before reporting ready, so it is normally
    # already here; the poll covers a box started by other means, and a slow
    # host.
    socket_path = session.paths.run / "ssh.sock"
    deadline = time.monotonic() + 20.0
    while not socket_path.exists() and time.monotonic() < deadline:
        time.sleep(0.2)
    if not socket_path.exists():
        print(
            f"!! {box.name} has no ssh channel at {socket_path} after 20s.\n"
            f"   The guest may have failed early - `asbx box diag` shows its console.",
            file=sys.stderr,
        )
        return EXIT_USAGE

    # ProxyCommand shells out to us: a tiny stdio<->unix relay, so we do not
    # depend on which netcat flavour happens to be installed.
    proxy = f"{shlex.quote(sys.executable)} -m agentsandbox.cli vsock-proxy {shlex.quote(str(socket_path))}"
    identity.write_client_config(box.name, proxy)

    if not _wait_for_sshd(socket_path, guest_logs=session.paths.guest_logs):
        print(
            f"!! {box.name} is up but its sshd never answered.\n"
            f"   `asbx box diag` shows the guest console; the bootstrap may have failed.",
            file=sys.stderr,
        )
        return EXIT_USAGE

    argv = ["ssh", "-F", str(identity.config), f"asbx-{box.name}"]
    if args.command:
        argv += ["--", *args.command]
    os.execvp("ssh", argv)  # replace ourselves; ssh owns the terminal from here
    return 0  # unreachable


def _guest_is_ready(guest_logs: Path | None) -> bool:
    """Has the bootstrap finished?

    Two signals, either of which counts. The marker file is the cheap one. The
    bootstrap log is the fallback, and it exists because the marker is written
    with `|| true` - it must never be able to abort a bootstrap that otherwise
    succeeded - and because a guest booted by an older version writes the log
    but not the marker. Requiring only the marker means waiting the full
    timeout for something that is never coming, on a guest that is perfectly
    healthy.
    """
    if guest_logs is None:
        return True
    if (guest_logs / "ready").exists():
        return True
    log = guest_logs / "bootstrap.log"
    if log.exists():
        return "[asbx-bootstrap] ready" in log.read_text(errors="replace")
    return False


def _wait_for_sshd(
    socket_path: Path, timeout: float = 180.0, guest_logs: Path | None = None
) -> bool:
    """Wait until the guest's sshd answers, by looking for its banner.

    ssh's own ConnectionAttempts does not help here: with a ProxyCommand, a
    proxy that exits is a fatal error rather than a retryable connect failure,
    so ssh gives up on the first try. And it gives up quietly - the symptom is
    `asbx box shell` returning instantly with no output at all.

    Connecting to the socket proves nothing either: vfkit accepts, then fails
    to dial the guest's vsock port and closes. Only the banner means sshd is
    actually listening.
    """
    import socket as _socket

    started = time.monotonic()
    deadline = started + timeout
    announced = False
    reported = 0
    while time.monotonic() < deadline:
        sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        sock.settimeout(5.0)
        try:
            sock.connect(str(socket_path))
            if sock.recv(4).startswith(b"SSH-"):
                # Reachable is not ready. sshd starts before the bootstrap, so
                # that a failed bootstrap still leaves a way in; a shell taken
                # in that window has no tunnel and no capability placeholders,
                # because the file holding them is still root-owned and the
                # profile script skips what it cannot read.
                if _guest_is_ready(guest_logs):
                    return True
        except OSError:
            pass
        finally:
            sock.close()
        if not announced:
            # A first boot installs packages before sshd is reachable. Silence
            # is indistinguishable from a hang, and so is a message with no
            # bound on it - say how long this will wait before giving up.
            print(
                f"waiting for {socket_path.parent.parent.name} to finish booting "
                f"(up to {int(timeout)}s)...",
                file=sys.stderr,
            )
            announced = True
        waited = int(time.monotonic() - started)
        if waited and waited // 15 > reported:
            reported = waited // 15
            print(f"  ... still booting ({waited}s)", file=sys.stderr)
        time.sleep(2.0)
    return False


def cmd_vsock_proxy(args: argparse.Namespace) -> int:
    """Relay stdin/stdout to a unix socket. Used as ssh's ProxyCommand."""
    import selectors
    import socket

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(args.socket)
    except OSError as exc:
        print(f"asbx: cannot reach the guest at {args.socket}: {exc.strerror}", file=sys.stderr)
        return 1

    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    selector = selectors.DefaultSelector()
    selector.register(stdin, selectors.EVENT_READ, "stdin")
    selector.register(sock, selectors.EVENT_READ, "sock")

    try:
        while True:
            for key, _ in selector.select():
                if key.data == "stdin":
                    chunk = stdin.read1(65536)
                    if not chunk:
                        return 0
                    sock.sendall(chunk)
                else:
                    chunk = sock.recv(65536)
                    if not chunk:
                        return 0
                    stdout.write(chunk)
                    stdout.flush()
    except (BrokenPipeError, ConnectionResetError, KeyboardInterrupt):
        return 0
    finally:
        sock.close()


#: How long to wait for a supervisor to exit. The guest powers itself off,
#: which takes a few seconds; well under this on any healthy box.
_STOP_TIMEOUT = 30.0


def _await_supervisor_exit(pid: int, timeout: float = _STOP_TIMEOUT) -> bool:
    """True once the supervisor is gone, False if it outlives the timeout."""
    deadline = time.monotonic() + timeout
    announced = False
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return True  # someone else's process now; ours is gone
        if not announced and time.monotonic() > deadline - timeout + 3:
            print("waiting for the guest to power off...", file=sys.stderr)
            announced = True
        time.sleep(0.25)
    return False


def cmd_box_stop(args: argparse.Namespace) -> int:
    """Stop the run belonging to a box (or the only running one)."""
    from .session import STATE_RUNNING

    running = [s for s in list_sessions() if s.state == STATE_RUNNING]
    if args.name:
        running = [s for s in running if s.box_name == args.name]
        if not running:
            print(f"!! {args.name} is not running", file=sys.stderr)
            return EXIT_USAGE
    elif not running:
        print("nothing is running")
        return 0
    elif len(running) > 1:
        listed = "\n".join(f"  {s.box_name or s.session_id}" for s in running)
        print(f"!! several are running - name one:\n{listed}", file=sys.stderr)
        return EXIT_USAGE

    session = running[0]
    name = session.box_name or session.session_id
    if session.supervisor_pid and session.supervisor_pid != os.getpid():
        try:
            os.kill(session.supervisor_pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        else:
            # Wait for it to actually be gone. Returning at the signal made
            # `asbx box stop neo && asbx box start neo` - the obvious way to
            # restart - race the shutdown and fail with "already running",
            # pointing at a session that was in the middle of exiting.
            if args.wait and _await_supervisor_exit(session.supervisor_pid):
                print(f"stopped {name}")
                return 0
            if not args.wait:
                print(f"asked {name} to stop")
                return 0
            print(
                f"!! {name} did not stop within {_STOP_TIMEOUT:.0f}s "
                f"(supervisor pid {session.supervisor_pid} still alive)",
                file=sys.stderr,
            )
            return 1
    stop_session_by_id(session.session_id, purge=args.purge)
    print(f"stopped {session.box_name or session.session_id}")
    return 0


def cmd_box_reset(args: argparse.Namespace) -> int:
    """Throw the guest filesystem away; the next start rebuilds from golden."""
    from .box import Box

    box = Box.load(args.name)
    if not box.has_disk:
        print(f"{box.name} has no disk yet; nothing to reset")
        return 0
    box.remove_disk()
    print(f"reset {box.name}; the next start rebuilds it from the golden image")
    return 0


def cmd_image_list(args: argparse.Namespace) -> int:
    from .vm.vfkit import images_dir, list_images

    images = list_images()
    if not images:
        print(f"no images built in {images_dir()}")
        print("  ./vm/build-image.sh                     debian (the default)")
        print("  ASBX_DISTRO=ubuntu ./vm/build-image.sh  ubuntu")
        return 0

    for image in images:
        size = image["bytes"] / (1024**3)
        line = f"{image['name']:<28} {size:>6.1f} GiB"
        if image.get("built_at"):
            line += f"  built {image['built_at']}"
        # Unknown is not the same as fine. An image with no metadata has never
        # been through prepare-image.sh as far as anything here can tell, and
        # saying nothing would read as a clean bill of health.
        if note := image.get("note"):
            line += f"  ({note})"
        if image.get("prepared") is False:
            line += "  !! not prepared - run ./vm/prepare-image.sh"
        elif image.get("prepared") is not True:
            line += "  ?  prepared state unknown"
        print(line)

    used = {}
    from .box import list_boxes

    for box in list_boxes():
        used.setdefault(box.image, []).append(box.name)
    if used:
        print("\nin use by:")
        for name, boxes in sorted(used.items()):
            print(f"  {name:<28} {', '.join(sorted(boxes))}")
    return 0


def _mitmweb_warning() -> str:
    return (
        "!! mitmweb keeps every flow it sees - headers and bodies - in memory.\n"
        "   Nothing else in this sandbox stores traffic, and the UI is readable\n"
        "   by anything on this Mac. It is capped at 2000 flows, but turn it\n"
        "   off when you are done rather than leaving it on for a long run:\n"
        "       asbx box web NAME --off"
    )


def cmd_web(args: argparse.Namespace) -> int:
    """Turn mitmweb on or off without restarting the box.

    Everything the guest depends on outlives the proxy process - the WireGuard
    keys are a file, the port is on the session record, the CA is in a
    per-session confdir - so a replacement listens on the same port with the
    same identity. The one thing that does not survive is the WireGuard
    session, which is why the supervisor clears the guest's before returning.
    """
    from .broker.server import read_token, send_command

    session = _resolve_session(args.name)
    attach = args.on
    try:
        reply = send_command(
            session.paths.broker_socket,
            read_token(session.paths.broker_token),
            f"web-attach:{args.port}" if attach else "web-detach",
        )
    except SandboxError as exc:
        print(f"!! {exc}", file=sys.stderr)
        return 1

    if not reply.get("ok"):
        print(f"!! {reply.get('error', 'unknown error')}", file=sys.stderr)
        return 1

    print(reply.get("message", ""))
    if url := reply.get("url"):
        print(f"  {url}")
    # Only an actual restart costs anything - "already attached/detached" is
    # a no-op the mitmproxy process never saw, so nothing was reset and there
    # is no tunnel to renegotiate. Printing the restart cost anyway would say
    # a request was dropped and packets are about to be lost when neither
    # happened.
    if reply.get("changed"):
        print("  connections in flight were reset")
        if reply.get("tunnel") == "renegotiated":
            print("  the guest's tunnel was renegotiated; it is usable now")
        else:
            print(
                "  the guest could not be asked to renegotiate its tunnel - expect\n"
                "  up to 15s of dropped packets before it re-handshakes on its own"
            )
    if attach:
        print()
        print(_mitmweb_warning(), file=sys.stderr)
    return 0


def cmd_image_rm(args: argparse.Namespace) -> int:
    """Delete a built image, unless a box still names it.

    Images are the largest thing this tool keeps - a 20 GiB sparse file each -
    and nothing removed them, so every distro ever tried stayed forever. A box
    that names a deleted image would fail at its next reset, so that is refused
    rather than discovered later.
    """
    from .box import list_boxes
    from .vm.vfkit import image_metadata_path, image_path

    raw = image_path(args.name)
    if not raw.exists():
        print(f"!! no image named {args.name!r}", file=sys.stderr)
        return EXIT_USAGE

    users = [box.name for box in list_boxes() if box.image == args.name]
    if users and not args.force:
        print(f"!! {args.name} is in use by: {', '.join(sorted(users))}", file=sys.stderr)
        print("   point them elsewhere with `asbx box set NAME --image ...`, or --force", file=sys.stderr)
        return EXIT_USAGE

    used = raw.stat().st_blocks * 512
    raw.unlink()
    image_metadata_path(args.name).unlink(missing_ok=True)
    print(f"removed {args.name} ({used / 1024**3:.1f} GiB reclaimed)")
    if users:
        print(f"!! still named by: {', '.join(sorted(users))} - they will fail to reset")
    return 0


def cmd_image_gc(args: argparse.Namespace) -> int:
    """Delete the downloaded cloud images kept after conversion.

    build-image.sh converts a .qcow2/.img into the raw file boxes clone, then
    leaves the download in place - useful only if the same image is rebuilt,
    which is rare, and costing most of a gigabyte each in the meantime.
    """
    from .vm.vfkit import images_dir

    downloads = sorted(
        path
        for suffix in ("*.qcow2", "*.img")
        for path in images_dir().glob(suffix)
    )
    if not downloads:
        print("nothing to collect")
        return 0

    total = 0
    for path in downloads:
        size = path.stat().st_blocks * 512
        total += size
        print(f"  {path.name}  {size / 1024**2:.0f} MiB")
        if not args.dry_run:
            path.unlink()
    verb = "would reclaim" if args.dry_run else "reclaimed"
    print(f"{verb} {total / 1024**3:.1f} GiB (re-downloaded automatically on the next build)")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    problems = check_host()
    if not problems:
        print("all good: mitmproxy, vfkit and a golden image are present")
        for line in _describe_images():
            print(f"  image  {line}")
        return 0
    for problem in problems:
        print(f"!! {problem}")
    return 1


def _describe_images() -> list[str]:
    """One line per built image, for `doctor`.

    Which distro a box runs is a property of the image it names, so
    this lists what exists rather than asserting a single answer.
    """
    from .vm.vfkit import list_images

    lines = []
    for image in list_images():
        distro = image.get("distro", "unknown distro")
        note = "" if image.get("prepared") is not False else "  !! not prepared"
        lines.append(f"{image['name']} ({distro}){note}")
    return lines or ["none built - run ./vm/build-image.sh"]


# ---------------------------------------------------------------------------
# parser


def _hidden_parser(sub, name: str) -> argparse.ArgumentParser:
    """Register a subcommand that does not appear in help at all.

    ``help=argparse.SUPPRESS`` is not enough on its own: argparse still keeps
    the entry and renders it as a literal "==SUPPRESS==" line. Dropping the
    pseudo-action is what actually hides it - from the usage line and the
    command list both.
    """
    parser = sub.add_parser(name, help=argparse.SUPPRESS)
    sub._choices_actions.pop()
    return parser


def _hide_suppressed_from_usage(sub) -> None:
    """Recompute a subparsers group's auto-generated ``{a,b,c}`` usage line.

    Popping from ``_choices_actions`` (what :func:`_hidden_parser` does) hides
    a command from the itemized help body, but the usage line's ``{...}`` is a
    separate metavar that argparse only auto-generates once, from every
    registered choice - it does not notice the pop. Call this after the last
    subcommand is registered on a group that has any hidden ones.
    """
    visible = [a.dest for a in sub._choices_actions if a.help is not argparse.SUPPRESS]
    sub.metavar = "{" + ",".join(visible) + "}"


def build_parser() -> argparse.ArgumentParser:
    """``asbx <resource> <action> [args]``, with one rule for naming a box:

    A command that *is* a box action (``box start``, ``box shell``, ...) takes
    the box name as its own bare positional - it is the thing being acted on.
    A command that acts on something *belonging to* a box (a capability, a
    secret) takes ``--box`` instead, because its positional slot already
    belongs to that other thing (a capability id, a request id). The check is
    mechanical: is the word right after ``asbx`` literally ``box``? Positional.
    Anything else? ``--box``.
    """
    parser = argparse.ArgumentParser(prog="asbx", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    # `--box` is shared, not redefined per leaf, so the six places that need
    # it (cap's four verbs, secret refresh) cannot drift out of sync with each
    # other. `add_help=False`: without it every leaf would register a second
    # `-h`, and argparse refuses that outright.
    box_flag = argparse.ArgumentParser(add_help=False)
    box_flag.add_argument("--box", help="which box (default: the only one running)")

    # -- box (the resource this tool exists for) -----------------------------
    box_parser = sub.add_parser("box", help="create, boot, and manage sandboxed VMs")
    box_sub = box_parser.add_subparsers(dest="subcommand", required=True)

    create = box_sub.add_parser("create", help="define a box (does not boot it)")
    create.add_argument("name")
    create.add_argument("--project", help="host directory to mount in the guest")
    create.add_argument("--mount-path", help="where it mounts inside (default: same as host)")
    create.add_argument("--profile", help="capability profile to issue on every start")
    create.add_argument("--allow", action="append", default=[], metavar="HOST",
                        help="restrict egress to these hosts (default: all public)")
    create.add_argument("--share", action="append", type=_parse_share, metavar="PATH:ro|rw",
                        help="extra host directory at /mnt/<name>")
    create.add_argument("--cpus", type=int, default=2)
    create.add_argument("--memory", type=int, default=2048, help="guest RAM in MiB")
    create.add_argument(
        "--image",
        default=DEFAULT_IMAGE,
        help=f"base image to clone the disk from (default: {DEFAULT_IMAGE}); see `asbx image ls`",
    )
    create.add_argument("--force", action="store_true", help="redefine an existing box")
    create.set_defaults(func=cmd_box_create)

    start = box_sub.add_parser("start", help="boot a box")
    start.add_argument("name")
    start.add_argument("--fresh", action="store_true", help="discard the disk and rebuild it")
    start.add_argument("--forward", action="append", type=_parse_forward, default=[],
                       metavar="[HOST:]GUEST", help="forward a guest port to localhost")
    start.add_argument("--dev-target", action="append", default=[], metavar="GUESTPORT:HOSTPORT",
                       help=argparse.SUPPRESS)
    start.add_argument("-a", "--attach", action="store_true",
                       help="keep it in the foreground with the guest console attached")
    start.add_argument("--netcheck", choices=["halt", "warn"], default="halt")
    start.set_defaults(func=cmd_box_start, vm=True, console=False)

    ls = box_sub.add_parser("ls", help="list boxes")
    ls.set_defaults(func=cmd_box_list)

    inspect = box_sub.add_parser("inspect", help="show a box's configuration")
    inspect.add_argument("name")
    inspect.set_defaults(func=cmd_box_inspect)

    status = box_sub.add_parser("status", help="show a box's live session")
    status.add_argument("name", nargs="?", help="box (default: the only one running)")
    status.set_defaults(func=cmd_box_status)

    rm = box_sub.add_parser("rm", help="delete a box and its disk")
    rm.add_argument("name")
    rm.add_argument("--keep-disk", action="store_true")
    rm.set_defaults(func=cmd_box_rm)

    shell = box_sub.add_parser("shell", help="open a shell in a running box")
    shell.add_argument("name", nargs="?", help="box (default: the only running one)")
    shell.add_argument("command", nargs=argparse.REMAINDER, help="run this instead of a shell")
    shell.set_defaults(func=cmd_shell)

    # `asbx box shell` shells out to us as ssh's ProxyCommand: `python -m
    # agentsandbox.cli vsock-proxy <socket>`, argv and all, so this has to
    # keep working as a top-level subcommand - moving it under `box` would
    # silently break every shell without a syntax error to point at why.
    proxy = _hidden_parser(sub, "vsock-proxy")
    proxy.add_argument("socket")
    proxy.set_defaults(func=cmd_vsock_proxy)

    stop_env = box_sub.add_parser("stop", help="stop a running box")
    stop_env.add_argument("name", nargs="?", help="box name (default: the only running one)")
    stop_env.add_argument("--purge", action="store_true", help="also erase the run's audit trail")
    stop_env.add_argument(
        "--no-wait",
        dest="wait",
        action="store_false",
        help="return as soon as the stop is requested, without waiting for it",
    )
    stop_env.set_defaults(func=cmd_box_stop, wait=True)

    set_cmd = box_sub.add_parser("set", help="change a box's cpus or memory")
    set_cmd.add_argument("name")
    set_cmd.add_argument("--memory", type=int, metavar="MIB", help="guest RAM in MiB")
    set_cmd.add_argument("--cpus", type=int)
    set_cmd.add_argument("--image", help="base image; takes effect on the next `asbx box reset`")
    set_cmd.set_defaults(func=cmd_box_set)

    reset = box_sub.add_parser("reset", help="discard a box's disk, keeping its config")
    reset.add_argument("name")
    reset.set_defaults(func=cmd_box_reset)

    web = box_sub.add_parser("web", help="turn the mitmweb traffic inspector on or off")
    web.add_argument("name", nargs="?", help="box (default: the only one running)")
    # A required choice, not a toggle: which way "asbx box web neo" would flip
    # depends on state the command line does not show, and getting it wrong is
    # silent - the opposite of what you want for something that starts keeping
    # every flow, headers and bodies, in memory. --on/--off are flags rather
    # than a second positional (`web attach`/`web detach`) so the command
    # stays `box web NAME [args]` - three words, like every other box command
    # - instead of reading as a fourth, verb-shaped argument.
    onoff = web.add_mutually_exclusive_group(required=True)
    onoff.add_argument("--on", action="store_true", help="turn mitmweb on")
    onoff.add_argument("--off", dest="on", action="store_false", help="turn mitmweb off")
    web.add_argument(
        "--port", type=int, default=0, metavar="N", help="fixed port (default: random)"
    )
    web.set_defaults(func=cmd_web)

    diag = box_sub.add_parser("diag", help="one-shot diagnostics for a misbehaving session")
    diag.add_argument(
        "name", nargs="?", help="box or session id (default: the most recent session, even if stopped)"
    )
    diag.add_argument("--tail", type=int, default=25, help="lines per log section")
    diag.set_defaults(func=cmd_diag)

    audit = box_sub.add_parser("audit", help="show a box's session audit log")
    audit.add_argument("name", nargs="?", help="box (default: the only one running)")
    audit.add_argument("--tail", type=int, default=50)
    audit.set_defaults(func=cmd_audit)

    # -- image ----------------------------------------------------------------
    image_parser = sub.add_parser("image", help="base images boxes clone from")
    image_sub = image_parser.add_subparsers(dest="subcommand", required=True)
    image_ls = image_sub.add_parser("ls", help="list built images")
    image_ls.set_defaults(func=cmd_image_list)
    image_rm = image_sub.add_parser("rm", help="delete a built image")
    image_rm.add_argument("name")
    image_rm.add_argument("--force", action="store_true", help="even if a box names it")
    image_rm.set_defaults(func=cmd_image_rm)
    image_gc = image_sub.add_parser("gc", help="delete downloads kept after conversion")
    image_gc.add_argument("--dry-run", action="store_true")
    image_gc.set_defaults(func=cmd_image_gc)

    # -- cap --------------------------------------------------------------
    cap = sub.add_parser("cap", help="capability management")
    cap_sub = cap.add_subparsers(dest="subcommand", required=True)

    issue = cap_sub.add_parser("issue", parents=[box_flag], help="mint a capability placeholder")
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
    issue.add_argument(
        "--ttl",
        type=int,
        default=DEFAULT_TTL_SECONDS,
        help="lifetime in seconds (0 = never expires, the default)",
    )
    issue.add_argument(
        "--max-response-bytes", type=int, default=DEFAULT_MAX_RESPONSE_BYTES
    )
    issue.add_argument("--label", default="")
    issue.set_defaults(func=cmd_cap_issue)

    cap_sub.add_parser("ls", parents=[box_flag], help="list capabilities").set_defaults(
        func=cmd_cap_list
    )

    try_cmd = cap_sub.add_parser(
        "try", parents=[box_flag], help="send one request through the broker, as the guest would"
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

    renew = cap_sub.add_parser("renew", parents=[box_flag], help="extend a capability that ran out")
    renew.add_argument("cap_id")
    renew.add_argument(
        "--ttl",
        type=int,
        required=True,
        help="seconds from now (0 = never expires)",
    )
    renew.set_defaults(func=cmd_cap_renew)

    revoke = cap_sub.add_parser("revoke", parents=[box_flag], help="revoke one capability, or 'all'")
    revoke.add_argument("cap_id")
    revoke.set_defaults(func=cmd_cap_revoke)

    # -- secret -----------------------------------------------------------
    secret = sub.add_parser("secret", help="credentials in the macOS keychain")
    secret_sub = secret.add_subparsers(dest="subcommand", required=True)
    secret_refresh = secret_sub.add_parser(
        "refresh", parents=[box_flag], help="re-read credentials into a running box"
    )
    secret_refresh.set_defaults(func=cmd_secret_refresh)

    # No --box: this writes to the Keychain directly, before any box exists
    # to name.
    secret_set = secret_sub.add_parser("set", help="store a credential (prompts, never echoes)")
    secret_set.add_argument("--service", required=True)
    secret_set.add_argument("--account", default="")
    secret_set.set_defaults(func=cmd_secret_set)

    # -- profile ------------------------------------------------------------
    # No --box either: a profile is a reusable declaration, referenced by
    # `--profile` at `box create` time - it does not belong to a running box.
    profile = sub.add_parser("profile", help="capability profiles")
    profile_sub = profile.add_subparsers(dest="subcommand", required=True)
    profile_ls = profile_sub.add_parser("ls", help="list available profiles")
    profile_ls.set_defaults(func=cmd_profile_list)
    profile_show = profile_sub.add_parser("show", help="show one profile's contents")
    profile_show.add_argument("name")
    profile_show.set_defaults(func=cmd_profile_show)

    # -- system ---------------------------------------------------------------
    # Host-wide, not scoped to any one box: `doctor` checks the Mac, and
    # `sessions`/`prune` sweep every session regardless of which box (or none,
    # for one since deleted) it came from. Neither `box` nor `cap` was ever
    # really the right home for `prune` - which is why it used to exist under
    # both, registered twice for the same function.
    system = sub.add_parser("system", help="host checks and cross-box bookkeeping")
    system_sub = system.add_subparsers(dest="subcommand", required=True)
    system_sub.add_parser("doctor", help="check the host prerequisites").set_defaults(
        func=cmd_doctor
    )
    system_sub.add_parser("sessions", help="list every session, across every box").set_defaults(
        func=cmd_system_sessions
    )
    prune = system_sub.add_parser("prune", help="delete stopped sessions' leftover state")
    prune.add_argument("--older-than", type=int, metavar="DAYS", help="only those older than N days")
    prune.add_argument("--dry-run", action="store_true")
    prune.set_defaults(func=cmd_system_prune)

    # Spell the usage line from the commands that are actually registered.
    # It used to be a hand-written string, which meant a new subcommand was
    # invisible in `asbx` until someone remembered to edit it in two places -
    # the command worked, but nobody could find it.
    _hide_suppressed_from_usage(sub)
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
