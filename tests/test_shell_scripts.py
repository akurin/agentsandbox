"""The shell scripts, checked for the mistakes shell makes easy.

These are not unit tests of behaviour - the scripts boot VMs and download
gigabytes. They guard the failure modes that are silent when they happen.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPTS = sorted(REPO.glob("vm/*.sh")) + sorted((REPO / "src/agentsandbox/vm/guest").glob("*.sh"))


def _unquoted_heredoc_bodies(text: str) -> list[tuple[int, str]]:
    """Every line inside a heredoc whose delimiter is *not* quoted.

    `cat <<EOF` interpolates; `cat <<'EOF'` does not. Only the first kind can
    run a command it was only meant to mention.
    """
    lines = text.splitlines()
    inside: str | None = None
    body: list[tuple[int, str]] = []
    for number, line in enumerate(lines, 1):
        if inside is not None:
            if line.strip() == inside:
                inside = None
            else:
                body.append((number, line))
            continue
        match = re.search(r"<<-?\s*([\"']?)([A-Za-z_][A-Za-z0-9_]*)\1", line)
        if match:
            quote, delimiter = match.group(1), match.group(2)
            if not quote:  # unquoted: expansions and backticks are live
                inside = delimiter
    return body


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_scripts_are_syntactically_valid(script):
    assert subprocess.run(["bash", "-n", str(script)]).returncode == 0


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_no_unescaped_backticks_in_an_interpolating_heredoc(script):
    """A backtick in an unquoted heredoc runs a command.

    This shipped: a banner said `asbx reset` in prose, so printing it executed
    `asbx reset`. Nothing was destroyed, but only because that subcommand
    happens to require a positional argument - the text simply lost the words
    it was trying to show, which is how it was noticed.
    """
    offenders = [
        (number, line)
        for number, line in _unquoted_heredoc_bodies(script.read_text())
        if re.search(r"(?<!\\)`", line)
    ]
    assert not offenders, "\n".join(f"  {script.name}:{n}: {line}" for n, line in offenders)


def test_the_build_banner_still_names_the_commands_it_recommends():
    """The symptom the backtick bug produced: a sentence with a hole in it."""
    banner = (REPO / "vm/build-image.sh").read_text()
    for command in ("asbx box create", "asbx box set", "asbx box reset", "prepare-image.sh"):
        assert command in banner


def test_an_image_is_marked_prepared_only_after_the_packages_are_confirmed():
    """The flag said "prepared" for an image with no wireguard-tools.

    prepare-image.sh used to set prepared=true and *then* check the guest's
    report for MISSING, so a failed provisioning boot left the image recorded
    as good and exited 1. Every later boot died at the tunnel while
    `asbx image ls` insisted the image was fine - the flag is only worth
    having if it cannot lie.
    """
    text = (REPO / "vm/prepare-image.sh").read_text()
    flip = text.index('s/"prepared": false/"prepared": true/')
    missing_check = text.index('grep -q MISSING')
    assert missing_check < flip, "the prepared flag is set before MISSING is checked"


def test_the_prepared_flag_is_not_written_through_a_silenced_failure():
    """`|| true` on the write would put the lie back, quietly."""
    text = (REPO / "vm/prepare-image.sh").read_text()
    for line in text.splitlines():
        if 's/"prepared": false' in line:
            assert "|| true" not in line
            assert "2>/dev/null" not in line


def test_the_bootstrap_mirrors_its_log_to_the_console():
    """The share can fail to mount; the console cannot.

    Logging only into /var/log/asbx meant a failed virtio-fs mount produced no
    bootstrap.log on the host - identical, from the outside, to a bootstrap
    that never ran. Two very different problems, one symptom, and no way to
    tell them apart without attaching a console by hand.
    """
    text = (REPO / "src/agentsandbox/vm/guest/bootstrap.sh").read_text()
    assert "/dev/hvc0" in text
    assert "did not mount" in text


def test_the_bootstrap_does_not_swallow_the_mount_failure():
    text = (REPO / "src/agentsandbox/vm/guest/bootstrap.sh").read_text()
    assert "mountpoint -q /var/log/asbx || mount" not in text


def test_hvc0_is_the_last_console_on_the_cmdline():
    """The last console= becomes /dev/console, and vfkit captures hvc0 only.

    With `console=hvc0 console=ttyS0` the primary console was ttyS0, which
    nothing reads - so console.log held kernel messages and then stopped dead
    the moment systemd started writing to /dev/console. A guest that failed
    after that point left no trace at all.
    """
    text = (REPO / "vm/prepare-image.sh").read_text()
    cmdline = next(line for line in text.splitlines() if "GRUB_CMDLINE_LINUX_DEFAULT=" in line)
    assert cmdline.index("console=hvc0") > cmdline.index("console=ttyS0")


def test_the_console_setting_is_verified_not_assumed():
    """An uncaptured console makes every later failure invisible, so a prepare
    that silently failed to set it is worse than one that fails."""
    text = (REPO / "vm/prepare-image.sh").read_text()
    assert "ASBX-CONSOLE" in text
    assert "console=hvc0' /boot/grub/grub.cfg" in text
    grub_update = next(line for line in text.splitlines() if "update-grub" in line)
    assert "|| true" not in grub_update


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_guest_commands_do_not_run_on_the_host(script):
    """`$(...)` inside a cloud-init runcmd entry must be escaped.

    The heredoc is unquoted - it has to expand $IMAGE_NAME - so an unescaped
    substitution runs where the file is written, on the Mac, instead of in the
    guest. `$(systemctl is-enabled ...)` did exactly that and reported
    "systemctl: command not found" from a script that never meant to run it
    locally.

    Substitutions that build the document itself ($(date), the package loop)
    are correct and stay; the rule is about commands addressed to the guest,
    which are the ones inside a runcmd entry.
    """
    offenders = []
    for number, line in _unquoted_heredoc_bodies(script.read_text()):
        is_guest_command = line.lstrip().startswith("- [") or "sh, -c" in line
        if is_guest_command and re.search(r"(?<!\\)\$\(", line):
            offenders.append(f"  {script.name}:{number}: {line.strip()}")
    assert not offenders, (
        "unescaped $( in a guest command - it will run on the host:\n" + "\n".join(offenders)
    )


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_unquoted_heredocs_only_reference_variables_the_script_sets(script):
    """`set -u` turns a stray $VAR in an unquoted heredoc into a fatal error.

    A comment explaining GRUB's $GRUB_CMDLINE_LINUX did exactly that: the
    heredoc expanded it, the variable was never set, and the script died at
    the `cat` line with "unbound variable" - pointing at the heredoc rather
    than at the prose inside it. Backticks in the same position were already
    covered; this is the other half of the same hazard.
    """
    text = script.read_text()
    assigned = set(re.findall(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=", text, re.M))
    assigned |= set(re.findall(r"for\s+([A-Za-z_][A-Za-z0-9_]*)\s+in", text))
    # `IFS= read -r -d '' NAME <<'BLOCK'` - a per-family runcmd fragment
    # built into a variable rather than assigned with `=`, so the pattern
    # above never sees it.
    assigned |= set(re.findall(r"read\s+-r\s+-d\s+''\s+([A-Za-z_][A-Za-z0-9_]*)", text))
    assigned |= {"HOME", "PATH", "PWD", "USER", "SHELL", "TMPDIR", "1", "@"}
    # Sourced from /etc/asbx/family.env (rendered by cloudinit.py's
    # render_family_env) - a real external file at boot time, so grep can't
    # see the assignment; its fixed set of field names is added by hand.
    if re.search(r"\.\s+/etc/asbx/family\.env", text):
        assigned |= {
            "CA_CERT_SOURCE_DIR",
            "CA_BUNDLE_PATH",
            "CA_TRUST_UPDATE_CMD",
            "STALE_CERT_CLEANUP_CMD",
        }

    unknown = []
    for number, line in _unquoted_heredoc_bodies(text):
        for name in re.findall(r"(?<!\\)\$\{?([A-Za-z_][A-Za-z0-9_]*)", line):
            if name not in assigned:
                unknown.append(f"  {script.name}:{number}: ${name}")
    assert not unknown, (
        "unquoted heredoc references variables this script never sets;\n"
        "escape them (\\$) or reword:\n" + "\n".join(unknown)
    )


def test_the_provisioning_cloud_config_renders_and_parses():
    """Render the user-data heredoc the way the script does, then parse it.

    A malformed cloud-config does not fail loudly: the guest boots, cloud-init
    logs an error nobody reads, and the image comes out looking prepared. This
    catches it on the host, where the message goes to a person.
    """
    document = _prepare_cloud_config(packages="wireguard-tools socat")
    assert document["runcmd"]
    assert "wireguard-tools" in document["packages"]


def test_wait_online_is_bounded_rather_than_masked():
    """Masking it stopped the guest booting at all.

    Units that require network-online.target fail outright when the unit
    behind it is masked, instead of waiting - and cloud-init-network is one of
    them, so runcmd never ran and no sshd ever appeared. A bounded timeout
    keeps the dependency chain intact and simply stops waiting. The unmask is
    needed because images built by the earlier version carry the mask, and a
    masked unit ignores drop-ins.
    """
    text = (REPO / "vm/prepare-image.sh").read_text()
    assert "systemctl mask systemd-networkd-wait-online.service" not in text
    assert "systemctl unmask systemd-networkd-wait-online.service" in text
    assert "--timeout=5" in text
    assert "ASBX-WAITONLINE" in text




def test_the_wait_online_dropin_is_a_valid_unit_file():
    """Built by printf inside a heredoc, it came out as one line with literal
    \\n, which systemd ignores - the unit kept its default two-minute timeout
    and nothing reported a problem. Delivered as a YAML file it cannot happen.
    """
    document = _prepare_cloud_config()
    dropin = next(
        f for f in document["write_files"] if "wait-online" in f["path"]
    )
    lines = dropin["content"].strip().splitlines()
    assert lines[0] == "[Service]"
    assert lines[1] == "ExecStart="          # the reset, required before an override
    assert "--timeout=5" in lines[2]
    assert "\\n" not in dropin["content"]    # literal backslash-n means it failed


def _prepare_cloud_config(*, packages: str = "socat") -> dict:
    """Render prepare-image.sh's user-data heredoc standalone, the way the
    script does, and parse it.

    The heredoc references a handful of per-family runcmd fragments
    (GRUB_RUNCMD, SSH_DISABLE_RUNCMD, NETWORK_BACKEND_RUNCMD, PKG_VERIFY_CMD)
    that the script itself builds earlier, branching on which guest family
    is being prepared - stood in for here with harmless placeholders, since
    what these tests check (the cloud-config parses, the wait-online
    drop-in is well-formed, netplan/DHCP handling) is the same regardless
    of family.
    """
    yaml = pytest.importorskip("yaml")
    text = (REPO / "vm/prepare-image.sh").read_text()
    heredoc = text[text.index('cat >"$WORK/user-data" <<EOF') : text.index('cat >"$WORK/meta-data"')]
    work = Path(tempfile.mkdtemp())
    script = (
        "set -euo pipefail\n"
        f"WORK={work}\n"
        f'PACKAGES="{packages}"\n'
        "GRUB_RUNCMD='  - [ \"true\" ]'\n"
        "SSH_DISABLE_RUNCMD='  - [ \"true\" ]'\n"
        "NETWORK_BACKEND_RUNCMD='  - [ \"true\" ]'\n"
        'PKG_VERIFY_CMD="true"\n'
        f"{heredoc}"
    )
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr

    rendered = (work / "user-data").read_text()
    assert rendered.startswith("#cloud-config")
    return yaml.safe_load(rendered.split("\n", 1)[1])


def test_netplan_is_removed_so_its_generator_cannot_override_the_timeout():
    """netplan writes a wait-online drop-in into /run/systemd/generator.late,
    which is applied after anything in /etc - so it overrode our timeout with
    `-o routable -i enp0s1`, a state the guest can never reach. Drop-in
    precedence cannot beat a generator, so netplan stops managing the NIC."""
    document = _prepare_cloud_config()
    flat = " ".join(" ".join(c) if isinstance(c, list) else str(c) for c in document["runcmd"])
    assert "/etc/netplan/" in flat
    paths = [f["path"] for f in document["write_files"]]
    assert "/etc/cloud/cloud.cfg.d/99-asbx-disable-network.cfg" in paths


def test_the_prepare_boot_keeps_its_own_networking():
    """Removing netplan leaves the *next* prepare boot with no way to reach the
    archive. It gets its own DHCP unit, removed again before poweroff so a
    session guest never finds it - it would sort ahead of 10-asbx.network."""
    document = _prepare_cloud_config()
    dhcp = next(f for f in document["write_files"] if "prepare-dhcp" in f["path"])
    assert "DHCP=yes" in dhcp["content"]
    assert dhcp["path"] < "/etc/systemd/network/10-asbx.network"  # sorts first, as needed

    flat = " ".join(" ".join(c) if isinstance(c, list) else str(c) for c in document["runcmd"])
    assert "05-asbx-prepare-dhcp.network" in flat  # and is cleaned up


# -- the tunnel re-handshake, run against a stub `wg` --------------------------


WG_STUB = """#!/bin/sh
echo "$*" >> "$WG_LOG"
case "$1 $3" in
    "showconf ")  echo "[Interface]"; echo "PrivateKey = KEY"; echo "[Peer]" ;;
esac
case "$1 $3" in
    "show peers")      echo "PEERPUBKEY" ;;
    "show endpoints")  printf 'PEERPUBKEY\\t192.168.127.1:51820\\n' ;;
esac
case "$1" in
    set) [ "${WG_FAIL_SET:-}" = "$2$5" ] && exit 1 ;;
esac
exit 0
"""


def _run_rehandshake(tmp_path, **env):
    """Run the re-handshake script with `wg` stubbed out, and return the log."""
    import os

    from agentsandbox.manager import _REHANDSHAKE

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "wg"
    stub.write_text(WG_STUB)
    stub.chmod(0o755)
    log = tmp_path / "wg.log"
    log.write_text("")

    environ = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "WG_LOG": str(log), **env}
    done = subprocess.run(
        ["sh", "-c", _REHANDSHAKE], capture_output=True, text=True, env=environ, check=False
    )
    return done, [line for line in log.read_text().splitlines() if line]


def test_the_rehandshake_drops_the_session_and_puts_the_peer_back(tmp_path):
    """Removing the peer is what discards the ephemeral keys. Re-adding it
    with the endpoint read back off the interface is what keeps this narrower
    than `wg-quick down && up` - no routes, no resolver, no nftables."""
    done, log = _run_rehandshake(tmp_path)

    assert done.returncode == 0, done.stderr
    removed = [i for i, line in enumerate(log) if line.startswith("set wg0 peer PEERPUBKEY remove")]
    added = [i for i, line in enumerate(log) if "endpoint 192.168.127.1:51820" in line]
    assert removed and added and removed[0] < added[0]
    assert "allowed-ips 0.0.0.0/0" in log[added[0]]
    assert "persistent-keepalive 25" in log[added[0]]


def test_a_failed_re_add_restores_the_configuration_it_captured(tmp_path):
    """The one outcome worse than a fifteen-second blackout is a guest left
    with no peer at all."""
    done, log = _run_rehandshake(tmp_path, WG_FAIL_SET="wg0endpoint")

    assert done.returncode == 6
    assert any(line.startswith("setconf wg0") for line in log)
    assert "restored the previous config" in done.stderr


def test_the_rehandshake_stops_before_touching_anything_it_cannot_read(tmp_path):
    """A peer with no endpoint yet is a guest that has never handshaked. There
    is no session to drop and nothing to put back."""
    no_endpoint = WG_STUB.replace("printf 'PEERPUBKEY\\t192.168.127.1:51820\\n'", "echo '(none)'")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "wg").write_text(no_endpoint)
    (bin_dir / "wg").chmod(0o755)
    log = tmp_path / "wg.log"
    log.write_text("")

    import os

    from agentsandbox.manager import _REHANDSHAKE

    done = subprocess.run(
        ["sh", "-c", _REHANDSHAKE],
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "WG_LOG": str(log)},
        check=False,
    )
    assert done.returncode == 4
    assert not any("remove" in line for line in log.read_text().splitlines())
