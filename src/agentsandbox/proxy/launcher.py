"""Starting mitmproxy in its hardened, session-scoped configuration.

Every option here is a security decision, so they are grouped and commented
rather than dumped in one list.  The two that matter most:

* ``confdir`` points at the session directory, so the CA is unique per session
  and its private key lives with the rest of the session's secrets.
* ``save_stream_file`` is never set, and ``--flow-detail 0`` keeps request
  bodies off stdout - the spec forbids keeping flow dumps.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from ..config import home
from ..errors import SessionError
from ..session import Session

VIEWCAP_PATH = Path(__file__).with_name("viewcap.py")
ADDON_PATH = Path(__file__).with_name("addon.py")


def mitmdump_path(*, web: bool = False) -> str:
    """Prefer the mitmdump next to the interpreter running us."""
    name = "mitmweb" if web else "mitmdump"
    candidate = Path(sys.executable).with_name(name)
    if candidate.exists():
        return str(candidate)
    found = shutil.which(name)
    if not found:
        raise SessionError(f"{name} not found; install with `pip install mitmproxy`")
    return found


def build_argv(session: Session, addon_path: Path = ADDON_PATH, *, web: bool = False) -> list[str]:
    paths = session.paths
    mode = (
        f"wireguard:{paths.wireguard_conf}"
        f"@{session.wg_listen_host}:{session.wg_listen_port}"
    )
    argv = [
        mitmdump_path(web=web),
        "--mode",
        mode,
        "--scripts",
        str(addon_path),
        # -- per-session identity -------------------------------------------
        "--set",
        f"confdir={paths.mitm_confdir}",
        # -- never persist traffic ------------------------------------------
    ]
    if not web:
        # mitmweb has its own UI for flow inspection; these are mitmdump-only.
        argv += [
            "--flow-detail",
            "0",
        ]
    else:
        # Only mitmweb keeps a flow list, and only mitmweb needs it bounded.
        argv += ["--scripts", str(VIEWCAP_PATH)]
    argv += [
        "--set",
        "save_stream_file=",
        "--set",
        "store_streamed_bodies=false",
        # -- no blind passthrough -------------------------------------------
        # ignore_hosts/allow_hosts/tcp_hosts/udp_hosts are deliberately NOT set
        # here. They default to empty, which is what we want, and `--set x=`
        # does not clear a sequence option - it sets it to [''], an empty regex
        # that matches *every* host. That would ignore every connection (a
        # blind tunnel with no interception) and route all UDP and TCP through
        # raw layers. The addon refuses to run if any of them is non-empty.
        "--set",
        "rawtcp=false",
        # -- protocols we do support ----------------------------------------
        "--set",
        "http2=true",
        "--set",
        "http3=true",
        "--set",
        "websocket=true",
        # -- upstream TLS is verified properly ------------------------------
        "--set",
        "ssl_insecure=false",
        "--set",
        "upstream_cert=true",
        # tls_version_{client,server}_min are left alone: mitmproxy already
        # defaults to TLS 1.2, and setting them explicitly walks a probe path
        # that crashes against OpenSSL 4 builds.
        # ECH would hide the SNI from our own policy checks.
        "--set",
        "strip_ech=true",
        # Alt-Svc would advertise an HTTP/3 endpoint that skips this gateway.
        "--set",
        "keep_alt_svc_header=false",
        # -- request hygiene -------------------------------------------------
        "--set",
        "validate_inbound_headers=true",
        "--set",
        "normalize_outbound_headers=true",
        "--set",
        "connection_strategy=lazy",
        # -- surface reduction ------------------------------------------------
        # No onboarding app: the guest gets its CA from the bootstrap, not from
        # an HTTP endpoint served by the proxy itself.
        "--set",
        "onboarding=false",
        "--set",
        "block_global=false",  # the guest's 10.0.0.1 is "private", not global
        "--set",
        "block_private=false",
        "-q",
    ]
    return argv


@dataclass
class MitmproxyProcess:
    """Owns the mitmdump child process for a session."""

    session: Session
    process: subprocess.Popen | None = None
    web: bool = False
    web_port: int = 0

    @property
    def log_path(self) -> Path:
        return self.session.paths.root / "mitmproxy.log"

    @property
    def web_url(self) -> str | None:
        if not self.web:
            return None
        port = self.web_port or 8081
        return f"http://127.0.0.1:{port}"

    def start(self) -> subprocess.Popen:
        argv = build_argv(self.session, web=self.web)
        if self.web and self.web_port:
            argv.insert(1, "--set")
            argv.insert(2, f"web_port={self.web_port}")
        env = dict(os.environ)
        env["ASBX_SESSION"] = self.session.session_id
        env["ASBX_HOME"] = str(home())
        # The addon imports agentsandbox; make sure it resolves even when
        # mitmdump comes from a different virtualenv.
        src_root = str(Path(__file__).resolve().parents[2])
        env["PYTHONPATH"] = os.pathsep.join(filter(None, [src_root, env.get("PYTHONPATH", "")]))

        fd = os.open(self.log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            self.process = subprocess.Popen(  # noqa: S603 - argv is built here, not user input
                argv,
                stdout=fd,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                env=env,
                start_new_session=True,
            )
        finally:
            os.close(fd)
        return self.process

    def stop(self, timeout: float = 5.0) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.process = None

    @property
    def pid(self) -> int:
        return self.process.pid if self.process else 0
