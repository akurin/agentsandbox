"""Real-VM integration suite.

Not part of `make test` / plain `pytest`: `testpaths = ["tests"]` in
pyproject.toml means this directory is invisible unless named explicitly
(`pytest tests_integration`, or `make test-integration`). It boots a real
guest under vfkit, needs Virtualization.framework entitlements the sandboxed
Bash tool doesn't always have, and each test here costs tens of seconds -
none of which belongs in the fast, hermetic suite everything else runs in.

Everything under a box name of the form `it-<hex>` is this suite's own; nothing
here ever touches a box you created by hand, even under a different
`ASBX_HOME` - box names and session ids are unrelated across the two.

Default image is `debian-13`, the same default `asbx box create` itself
uses - this suite verifies the actual default experience, not a
convenient stand-in for it. Override with `ASBX_TEST_IMAGE` (e.g.
`ubuntu-26.04`) to run it against a different image.
"""

from __future__ import annotations

import platform
import shutil

import pytest
from helpers import (
    ASBX,
    asbx,
    current_session,
    gateway_stats,
    new_box_name,
    wait_for_condition,
    wait_for_console,
)

DEFAULT_TEST_IMAGE = "debian-13"


def _integration_env_problem() -> str | None:
    """Why this suite can't run here, or None if it can."""
    if platform.system() != "Darwin":
        return "requires macOS (Virtualization.framework)"
    if not ASBX.exists():
        return f"asbx not found at {ASBX} - run `make install` first"
    if shutil.which("vfkit") is None:
        import os

        if not os.path.exists("/opt/podman/bin/vfkit"):
            return "vfkit not found - `brew install vfkit`, or use Podman's bundled copy"
    result = asbx("image", "ls", check=False)
    if result.returncode != 0 or "no images built" in result.stdout:
        return "no image built - run `make vm-image && make vm-prepare` first"
    return None


@pytest.fixture(scope="session", autouse=True)
def integration_env():
    problem = _integration_env_problem()
    if problem:
        pytest.skip(f"integration environment not available: {problem}")


@pytest.fixture(scope="session")
def test_image() -> str:
    import os

    return os.environ.get("ASBX_TEST_IMAGE", DEFAULT_TEST_IMAGE)


def _boot_box(image: str, *, allow: list[str], name: str | None = None):
    """Create, start, and wait for a fresh box to be genuinely usable.

    Returns ``(box_name, session)``. The caller owns teardown.

    "Usable" means more than the guest's own bootstrap script reporting
    success: `[asbx-bootstrap] ready` on the console only means the guest
    *believes* it configured its side of the tunnel. Observed directly,
    intermittently, in this same environment: a box reports ready and stays
    running, but the L2 gateway never relays a real frame - `frames_in`
    stuck at 1 (one stray probe) for the box's entire lifetime. Every test
    that needs real network access from inside the guest would otherwise
    hang on a dead tunnel with a confusing ssh-timeout stack trace instead
    of a clear "the tunnel never came up" failure right here, at setup.
    """
    box_name = name or new_box_name()
    asbx("box", "create", box_name, "--image", image, "--allow", ",".join(allow))
    asbx("box", "start", box_name, timeout=60)
    session = current_session(box_name)
    assert session is not None, f"{box_name} reports started but no RUNNING session was found"
    wait_for_console(session, ready="[asbx-bootstrap] ready")
    # Generous: a healthy tunnel normally handshakes in a couple of seconds,
    # but this host may be running other real VMs at the same time (this
    # suite is not the only thing that boots one), and WireGuard's handshake
    # timing is exactly the kind of thing CPU contention delays.
    wait_for_condition(
        lambda: gateway_stats(session).get("relayed", 0) > 0,
        timeout=60,
        description=f"the L2 gateway to relay a real frame for {box_name} (tunnel never came up)",
    )
    return box_name, session


def _teardown_box(box_name: str) -> None:
    asbx("box", "stop", box_name, check=False, timeout=30)
    asbx("box", "rm", box_name, check=False, timeout=30)


@pytest.fixture(scope="module")
def booted_box(test_image):
    """One box, shared by every test in a module - boot is the expensive
    part, and most tests in a file want the same running guest rather than
    a fresh one each.

    `box_name` is minted before the `try` and `_boot_box` runs inside it:
    `box create`/`box start` succeeding but the tunnel-readiness check then
    failing must still reach `_teardown_box`, or a box that boots but never
    gets a working tunnel leaks forever - observed directly, the first time
    this fixture had the call outside the `try`.
    """
    box_name = new_box_name()
    try:
        _, session = _boot_box(test_image, allow=["api.github.com"], name=box_name)
        yield box_name, session
    finally:
        _teardown_box(box_name)


@pytest.fixture
def fresh_box(test_image):
    """A box of its own, for a test that needs different `--allow` or
    otherwise can't share `booted_box`'s policy."""
    box_name = new_box_name()

    def _make(allow: list[str]):
        return _boot_box(test_image, allow=allow, name=box_name)

    try:
        yield _make
    finally:
        _teardown_box(box_name)
