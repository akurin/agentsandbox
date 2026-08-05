"""Session lifecycle and the CLI, including revocation on teardown."""

from __future__ import annotations

import json
import os

import pytest

from agentsandbox import cli
from agentsandbox.broker.server import (
    BrokerServer,
    InProcessBrokerClient,
    UnixBrokerClient,
    issue_token,
    read_token,
)
from agentsandbox.capabilities import CapabilityStore
from agentsandbox.errors import BrokerError
from agentsandbox.manager import SessionManager
from agentsandbox.session import STATE_STOPPED

from helpers import make_request, unix_sockets_available




# -- creation ----------------------------------------------------------------


def test_create_makes_a_complete_private_session(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    (project / "main.py").write_text("x = 1\n")

    manager = SessionManager.create(allow_hosts=["api.github.com"], project=project, label="demo")
    paths = manager.session.paths

    assert paths.root.stat().st_mode & 0o077 == 0
    assert paths.wireguard_conf.exists()
    assert paths.guest_wireguard_conf.exists()
    assert paths.broker_token.exists()
    # The project is a direct share, not a copy
    assert any(s.path == str(project) for s in manager.session.shares)
    for secret_file in (paths.wireguard_conf, paths.guest_wireguard_conf, paths.broker_token):
        assert secret_file.stat().st_mode & 0o077 == 0, secret_file


def test_sessions_do_not_share_identities(tmp_path):
    first = SessionManager.create(allow_hosts=["example.com"])
    second = SessionManager.create(allow_hosts=["example.com"])
    assert first.session.session_id != second.session.session_id
    assert (
        first.session.paths.wireguard_conf.read_text()
        != second.session.paths.wireguard_conf.read_text()
    )
    assert first.session.wg_listen_port != second.session.wg_listen_port


def test_a_capability_is_scoped_to_the_session_that_issued_it():
    first = SessionManager.create(allow_hosts=["api.github.com"])
    second = SessionManager.create(allow_hosts=["api.github.com"])

    token, cap = cli_issue(first)
    assert first.store.lookup(token) is not None
    # The other session's store has never heard of it.
    assert second.store.lookup(token) is None


def cli_issue(manager: SessionManager):
    from agentsandbox.capabilities import CapabilitySpec, SecretRef

    return manager.issue_capability(
        CapabilitySpec(
            provider="github",
            hosts=["api.github.com"],
            secret=SecretRef(backend="static", service="github-token"),
        )
    )


# -- teardown ----------------------------------------------------------------


def test_stopping_a_session_revokes_every_capability():
    manager = SessionManager.create(allow_hosts=["api.github.com"])
    token, cap = cli_issue(manager)

    manager.stop()

    assert manager.session.state == STATE_STOPPED
    assert manager.store.lookup(token).revoked is True


def test_purge_erases_all_session_state():
    manager = SessionManager.create(allow_hosts=["api.github.com"])
    cli_issue(manager)
    root = manager.session.paths.root

    manager.stop(purge=True)
    assert not root.exists()


def test_a_stopped_session_brokers_nothing(session, store, executor, resolver):
    """Revocation is what makes teardown safe, so check it end to end."""
    from agentsandbox.broker.approvals import AllowAll
    from agentsandbox.broker.core import BrokerCore
    from agentsandbox.capabilities import CapabilitySpec, SecretRef

    core = BrokerCore(
        session.session_id, store, session.policy, resolver, approvals=AllowAll(), executor=executor
    )
    token, _ = store.issue(
        CapabilitySpec(
            provider="github", hosts=["api.github.com"], secret=SecretRef(service="github-token")
        )
    )
    assert core.handle(make_request(token)).decision == "allow"

    SessionManager(session).revoke_all()
    assert core.handle(make_request(token)).reason == "capability_revoked"


# -- broker transport --------------------------------------------------------


def test_broker_token_file_is_owner_only(tmp_path):
    path = tmp_path / "broker.token"
    token = issue_token(path)
    assert path.stat().st_mode & 0o077 == 0
    assert read_token(path) == token


def test_a_group_readable_token_is_rejected(tmp_path):
    import os

    path = tmp_path / "broker.token"
    issue_token(path)
    os.chmod(path, 0o644)
    with pytest.raises(BrokerError):
        read_token(path)


def test_in_process_client_matches_the_core(broker, github_capability):
    token, _ = github_capability
    client = InProcessBrokerClient(broker)
    assert client.call(make_request(token)).decision == "allow"


def test_unix_transport_round_trip(tmp_path, session, broker, github_capability):
    if not unix_sockets_available(tmp_path):
        pytest.skip("outbound unix sockets are blocked in this box")

    token_path = session.paths.broker_token
    token = issue_token(token_path)
    server = BrokerServer(broker, session.paths.broker_socket, token)
    server.serve_in_thread()
    try:
        client = UnixBrokerClient(session.paths.broker_socket, token)
        cap_token, _ = github_capability
        response = client.call(make_request(cap_token))
        assert response.decision == "allow"

        wrong = UnixBrokerClient(session.paths.broker_socket, "not-the-token")
        assert wrong.call(make_request(cap_token)).reason == "unauthenticated"
    finally:
        server.shutdown()
        server.server_close()


def test_broker_socket_is_owner_only(session, broker):
    token = issue_token(session.paths.broker_token)
    server = BrokerServer(broker, session.paths.broker_socket, token)
    try:
        assert session.paths.broker_socket.stat().st_mode & 0o077 == 0
    finally:
        server.server_close()


def test_client_fails_closed_when_the_broker_is_absent(session):
    client = UnixBrokerClient(session.paths.run / "missing.sock", "token")
    with pytest.raises(BrokerError):
        client.call(make_request("cap_v1_whatever0123456789012"))


# -- CLI ---------------------------------------------------------------------


def test_cli_issue_list_and_revoke(capsys, monkeypatch):
    manager = SessionManager.create(allow_hosts=["api.github.com"], label="cli-test")
    monkeypatch.setenv("ASBX_SESSION", manager.session.session_id)

    assert cli.main(
        [
            "cap",
            "issue",
            "--provider",
            "github",
            "--host",
            "api.github.com",
            "--secret",
            "keychain:asbx-github:bot",
            "--ttl",
            "600",
        ]
    ) == 0
    issued = capsys.readouterr().out
    token = next(word for word in issued.split() if word.startswith("cap_v1_"))

    assert cli.main(["cap", "list"]) == 0
    listed = capsys.readouterr().out
    # The listing shows the short id, never the placeholder.
    assert token not in listed
    cap_id = json.loads(listed)[0]["cap_id"]

    assert cli.main(["cap", "revoke", cap_id]) == 0
    capsys.readouterr()

    store = CapabilityStore(manager.session.paths.capabilities, manager.session.session_id)
    assert store.lookup(token).revoked is True


def test_cli_session_list_and_status(capsys, monkeypatch):
    manager = SessionManager.create(allow_hosts=["example.com"], label="statustest")
    monkeypatch.setenv("ASBX_SESSION", manager.session.session_id)

    assert cli.main(["session", "list"]) == 0
    assert manager.session.session_id in capsys.readouterr().out

    assert cli.main(["session", "status"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["session"] == manager.session.session_id
    assert status["allow_hosts"] == ["example.com"]


def test_cli_session_with_project_adds_a_share(capsys):
    """`--project` mounts the directory directly, no copy step."""
    manager = SessionManager.create(allow_hosts=["example.com"], label="projtest")
    assert manager.session.project_path == ""
    assert not any(s.tag == "project" for s in manager.session.shares)
    # With --project, a share is added
    from pathlib import Path

    proj = Path(__file__).parent
    manager2 = SessionManager.create(allow_hosts=["example.com"], project=proj)
    assert any(s.tag == "project" for s in manager2.session.shares)


def test_cli_audit_shows_events(capsys, monkeypatch):
    manager = SessionManager.create(allow_hosts=["example.com"])
    monkeypatch.setenv("ASBX_SESSION", manager.session.session_id)
    assert cli.main(["audit"]) == 0
    assert "session.created" in capsys.readouterr().out


def test_cli_reports_a_missing_session_without_a_traceback(capsys, monkeypatch):
    monkeypatch.setenv("ASBX_SESSION", "does-not-exist")
    assert cli.main(["cap", "list"]) == cli.EXIT_DENIED
    assert "no such session" in capsys.readouterr().err


def test_share_argument_parsing(tmp_path):
    directory = tmp_path / "docs"
    directory.mkdir()
    assert cli._parse_share(f"{directory}:ro").read_only is True
    assert cli._parse_share(f"{directory}:rw").read_only is False
    assert cli._parse_share(str(directory)).read_only is True  # default is read-only

    with pytest.raises(Exception):
        cli._parse_share(f"{directory}:write")


def test_secret_reference_parsing():
    ref = cli._parse_secret_ref("keychain:asbx-github:bot")
    assert (ref.backend, ref.service, ref.account) == ("keychain", "asbx-github", "bot")
    with pytest.raises(Exception):
        cli._parse_secret_ref("vault:thing")


def test_unset_pids_are_never_treated_as_running():
    """`os.kill(0, sig)` hits the whole process group - pid 0 must be inert."""
    from agentsandbox import manager

    assert manager._is_alive(0) is False
    assert manager._is_alive(-1) is False
    manager._terminate(0)  # must be a no-op, not a group-wide SIGTERM


def test_status_reports_liveness_from_pids_in_another_process():
    manager = SessionManager.create(allow_hosts=["example.com"])
    status = manager.status()
    assert status["proxy_running"] is False
    assert status["vm_running"] is False
    assert status["supervisor_running"] is False

    manager.session.mitm_pid = os.getpid()
    assert manager.status()["proxy_running"] is True


def test_cap_try_reports_a_denial_without_calling_upstream(capsys, monkeypatch, tmp_path):
    """`asbx cap try` is the debugging tool for "why did I get a 403?\""""
    manager = SessionManager.create(allow_hosts=["api.github.com"])
    monkeypatch.setenv("ASBX_SESSION", manager.session.session_id)
    token, _ = cli_issue(manager)

    # A host the capability does not cover: denied before any network happens.
    assert cli.main(["cap", "try", token, "--url", "https://example.com/x"]) == cli.EXIT_DENIED
    out = capsys.readouterr().out
    assert "DENY" in out
    assert "host_not_allowlisted" in out


def test_cap_try_rejects_a_malformed_url(capsys, monkeypatch):
    manager = SessionManager.create(allow_hosts=["api.github.com"])
    monkeypatch.setenv("ASBX_SESSION", manager.session.session_id)
    assert cli.main(["cap", "try", "cap_v1_x", "--url", "not-a-url"]) == cli.EXIT_USAGE


def test_check_ipc_passes_or_explains_itself():
    """On a normal machine this is empty; in a sandbox it must say why."""
    from agentsandbox.manager import check_ipc

    for problem in check_ipc():
        assert "shell" in problem  # actionable, not just an errno


def test_session_guest_config_matches_the_gateway_endpoint():
    """End to end: what we write must be what the gateway will accept."""
    from agentsandbox.vm.gateway import GatewayConfig

    manager = SessionManager.create(allow_hosts=["api.github.com"])
    config = manager.session.paths.guest_wireguard_conf.read_text()
    gateway = GatewayConfig()

    assert f"Endpoint = {gateway.gateway_ip}:{gateway.gateway_port}" in config
    # The host's real listener is a different, random port and stays private.
    assert str(manager.session.wg_listen_port) not in config


def test_diag_survives_a_session_with_no_logs_yet(capsys, monkeypatch):
    """`asbx diag` must work on a broken session, which is when it is used."""
    manager = SessionManager.create(allow_hosts=["api.github.com"])
    monkeypatch.setenv("ASBX_SESSION", manager.session.session_id)

    assert cli.main(["diag"]) == 0
    out = capsys.readouterr().out
    assert "l2 gateway" in out
    assert "guest endpoint config" in out
    assert "Endpoint = 192.168.127.1:51820" in out
    assert "no gateway stats" in out  # not running: says so rather than crashing


def test_session_start_with_profile_issues_all_capabilities(tmp_path, monkeypatch):
    """`asbx session start --profile X` issues everything the profile declares.

    Tested at the manager level to avoid the polling loop in cmd_session_start.
    """
    profile_dir = tmp_path / "profiles"
    profile_dir.mkdir()
    (profile_dir / "testproj.json").write_text(json.dumps({
        "version": 1,
        "capabilities": [
            {"provider": "github", "hosts": ["api.github.com"], "secret": "keychain:asbx-github:bot", "methods": ["GET"]},
            {"provider": "npm", "hosts": ["registry.npmjs.org"], "secret": "keychain:asbx-npm:bot", "methods": ["GET"]},
        ],
    }))
    monkeypatch.setenv("ASBX_PROFILE_DIR", str(profile_dir))

    manager = SessionManager.create(allow_hosts=["api.github.com", "registry.npmjs.org"])
    issued = manager.issue_from_profile("testproj")
    assert len(issued) == 2
    assert all(isinstance(tok, str) and tok.startswith("cap_v1_") for tok, _ in issued)


# -- session resolution ------------------------------------------------------


def test_ambiguous_session_is_an_error_not_a_guess(monkeypatch):
    """Silently picking the newest is how you revoke on the wrong project."""
    from agentsandbox.errors import SessionError
    from agentsandbox.session import STATE_RUNNING, resolve_session_id

    monkeypatch.delenv("ASBX_SESSION", raising=False)
    for label in ("frontend", "backend"):
        m = SessionManager.create(allow_hosts=["example.com"], label=label)
        m.session.state = STATE_RUNNING
        m.session.save()

    with pytest.raises(SessionError) as exc:
        resolve_session_id(None)
    assert "2 sessions are running" in str(exc.value)
    assert "frontend" in str(exc.value)
    assert "backend" in str(exc.value)


def test_a_single_running_session_needs_no_flag(monkeypatch):
    from agentsandbox.session import STATE_RUNNING, resolve_session_id

    monkeypatch.delenv("ASBX_SESSION", raising=False)
    manager = SessionManager.create(allow_hosts=["example.com"])
    manager.session.state = STATE_RUNNING
    manager.session.save()
    assert resolve_session_id(None) == manager.session.session_id


def test_explicit_session_wins_over_ambiguity(monkeypatch):
    from agentsandbox.session import STATE_RUNNING, resolve_session_id

    monkeypatch.delenv("ASBX_SESSION", raising=False)
    first = SessionManager.create(allow_hosts=["example.com"], label="a")
    second = SessionManager.create(allow_hosts=["example.com"], label="b")
    for m in (first, second):
        m.session.state = STATE_RUNNING
        m.session.save()
    assert resolve_session_id(second.session.session_id) == second.session.session_id


def test_no_sessions_says_so_plainly(monkeypatch):
    from agentsandbox.errors import SessionError
    from agentsandbox.session import resolve_session_id

    monkeypatch.delenv("ASBX_SESSION", raising=False)
    with pytest.raises(SessionError, match="no sessions exist"):
        resolve_session_id(None)


def test_cap_list_works_across_sessions_without_a_target(capsys, monkeypatch):
    """Listing is read-only, so it does not need the session that issuing does."""
    monkeypatch.delenv("ASBX_SESSION", raising=False)
    first = SessionManager.create(allow_hosts=["api.github.com"], label="one")
    second = SessionManager.create(allow_hosts=["api.github.com"], label="two")
    cli_issue(first)
    cli_issue(second)

    assert cli.main(["cap", "list"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert len({c["session"] for c in listed}) == 2


def test_cap_list_with_no_sessions_is_not_an_error(capsys, monkeypatch):
    monkeypatch.delenv("ASBX_SESSION", raising=False)
    assert cli.main(["cap", "list"]) == 0
    assert "no sessions" in capsys.readouterr().out


def test_prune_removes_only_stopped_sessions(monkeypatch):
    """Stopped sessions are corpses; running ones must survive a prune."""
    from agentsandbox.session import STATE_RUNNING, list_sessions

    monkeypatch.delenv("ASBX_SESSION", raising=False)
    dead = SessionManager.create(allow_hosts=["example.com"], label="dead")
    dead.stop()
    alive = SessionManager.create(allow_hosts=["example.com"], label="alive")
    alive.session.state = STATE_RUNNING
    alive.session.save()

    assert cli.main(["session", "prune"]) == 0
    remaining = {s.session_id for s in list_sessions()}
    assert alive.session.session_id in remaining
    assert dead.session.session_id not in remaining


def test_prune_dry_run_deletes_nothing(capsys, monkeypatch):
    from agentsandbox.session import list_sessions

    monkeypatch.delenv("ASBX_SESSION", raising=False)
    manager = SessionManager.create(allow_hosts=["example.com"])
    manager.stop()

    assert cli.main(["session", "prune", "--dry-run"]) == 0
    assert "would remove" in capsys.readouterr().out
    assert len(list_sessions()) == 1


def test_session_list_explains_that_stopped_means_gone(capsys, monkeypatch):
    monkeypatch.delenv("ASBX_SESSION", raising=False)
    manager = SessionManager.create(allow_hosts=["example.com"])
    manager.stop()

    assert cli.main(["session", "list"]) == 0
    out = capsys.readouterr().out
    assert "cannot be resumed" in out
    assert "prune" in out


def test_the_control_socket_takes_registered_commands(session, broker, tmp_path):
    """The broker runs inside the supervisor, so its socket is the only
    authenticated way a CLI process can reach a running session. That is what
    lets mitmweb be attached without restarting the box."""
    from agentsandbox.broker.server import BrokerServer

    server = BrokerServer(broker, tmp_path / "b.sock", "tok")
    try:
        calls = []
        server.commands["web-attach"] = lambda port: (calls.append(port), {"ok": True, "url": "u"})[1]

        assert json.loads(server.handle_command("web-attach")) == {"ok": True, "url": "u"}
        assert json.loads(server.handle_command("web-attach:8081"))["ok"] is True
        assert calls == ["", "8081"]
        assert json.loads(server.handle_command("nope"))["ok"] is False
    finally:
        server.server_close()


def test_a_failing_command_is_reported_not_fatal(session, broker, tmp_path):
    """A handler that raises must not take the supervisor down with it - the
    supervisor is holding the guest, the gateway and the broker."""
    from agentsandbox.broker.server import BrokerServer

    server = BrokerServer(broker, tmp_path / "b2.sock", "tok")
    try:
        def _boom(_argument):
            raise RuntimeError("mitmproxy would not start")

        server.commands["web-attach"] = _boom
        reply = json.loads(server.handle_command("web-attach"))
        assert reply["ok"] is False
        assert "would not start" in reply["error"]
    finally:
        server.server_close()
