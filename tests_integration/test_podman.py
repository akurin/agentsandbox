"""Rootless Podman inside a guest: does its default network mode (pasta)
actually reach the tunnel, and does a container/build actually trust the
session CA - both real failures a user hit, both now fixed by config
bootstrap.sh bakes in on every boot (see the "let rootless Podman containers
reach the tunnel and trust its CA too" section) rather than something to
discover and configure by hand every time.

Podman itself is not part of the golden image - the golden image only ships
what the tunnel bootstrap itself needs (see vm/prepare-image.sh) - so this
suite installs it fresh on every boot, the same way a real user would.
"""

from __future__ import annotations

from helpers import asbx, current_session, gateway_stats, new_box_name, ssh_run, wait_for_condition, wait_for_console

#: Keyed by guest family, not image name - ubuntu-26.04 and debian-13 share
#: apt, fedora-44 uses dnf.
_INSTALL_PODMAN = {
    "debian": "sudo apt-get update -qq && sudo apt-get install -y -qq podman",
    "fedora": "sudo dnf install -y -q podman",
}

#: A small, fast, well-known-good container distro to build - this test is
#: about whether bootstrap.sh's baked-in config works by default, not about
#: re-verifying every container distro's own CA-trust quirks (Fedora needing
#: `update-ca-trust` before any `dnf install`, Alpine needing an http
#: bootstrap fallback) - those are facts about those images, independent of
#: which asbx guest family is hosting them, established and documented
#: directly in bootstrap.sh's own comment rather than re-proven here per
#: guest image.
_CONTAINERFILE = """FROM debian:trixie-slim
RUN apt-get update && apt-get install -y curl ca-certificates && update-ca-certificates
RUN curl -sS -o /dev/null -w "http_code=%{http_code}\\n" https://api.github.com
"""

_BUILD_SCRIPT = (
    "set -e\n"
    "mkdir -p /tmp/asbx-podman-test\n"
    "cat > /tmp/asbx-podman-test/Containerfile <<'CONTAINERFILE_EOF'\n"
    + _CONTAINERFILE
    + "CONTAINERFILE_EOF\n"
    "cd /tmp/asbx-podman-test && podman build -t asbx-podman-test .\n"
)


def _family(image: str) -> str:
    return "fedora" if image.startswith("fedora") else "debian"


def _start_and_wait(box_name: str):
    """Mirrors conftest.py's `_boot_box`, minus the `box create` - see
    test_disk_resize.py for why this suite keeps its own copy rather than
    sharing booted_box/fresh_box, which have no way to express "start,
    change guest state, start again"."""
    asbx("box", "start", box_name, timeout=60)
    session = current_session(box_name)
    assert session is not None, f"{box_name} reports started but no RUNNING session was found"
    wait_for_console(session, ready="[asbx-bootstrap] ready")
    wait_for_condition(
        lambda: gateway_stats(session).get("relayed", 0) > 0,
        timeout=60,
        description=f"the L2 gateway to relay a real frame for {box_name} (tunnel never came up)",
    )
    return session


def test_podman_build_reaches_the_tunnel_and_trusts_the_session_ca_by_default(test_image):
    """Zero `--network`, zero `-v`/`-e` flags: a plain `podman build` has to
    work purely off what bootstrap.sh already wrote, on every guest family
    asbx ships - the same failure this whole feature exists to fix
    (`podman build`'s own `apt-get install` getting no network at all)."""
    box_name = new_box_name()
    try:
        asbx("box", "create", box_name, "--image", test_image, "--allow", "*")
        _start_and_wait(box_name)

        install = ssh_run(box_name, _INSTALL_PODMAN[_family(test_image)], timeout=180)
        assert install.returncode == 0, f"installing podman failed on {test_image}: {install.stderr}"

        config_check = ssh_run(
            box_name,
            "test -f /etc/containers/containers.conf.d/99-asbx-pasta.conf "
            "&& test -f /etc/containers/mounts.conf",
        )
        assert config_check.returncode == 0, (
            f"bootstrap.sh did not write the podman config on {test_image}: {config_check.stderr}"
        )

        build = ssh_run(box_name, _BUILD_SCRIPT, timeout=180)
        assert build.returncode == 0, f"podman build failed on {test_image}:\n{build.stdout}\n{build.stderr}"
        assert "http_code=200" in build.stdout, (
            f"container never reached the tunnel/CA correctly on {test_image}:\n{build.stdout}"
        )
    finally:
        asbx("box", "stop", box_name, check=False, timeout=30)
        asbx("box", "rm", box_name, check=False, timeout=30)
