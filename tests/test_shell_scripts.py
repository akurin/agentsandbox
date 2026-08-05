"""The shell scripts, checked for the mistakes shell makes easy.

These are not unit tests of behaviour - the scripts boot VMs and download
gigabytes. They guard the failure modes that are silent when they happen.
"""

from __future__ import annotations

import re
import subprocess
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
    for command in ("asbx create", "asbx set", "asbx reset", "prepare-image.sh"):
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
