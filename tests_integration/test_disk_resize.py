"""`box set --disk-size` only grows the raw file on the host; the guest's
own partition and filesystem are expected to grow to match on their own, via
asbx-growroot.service - a systemd unit baked into the golden image (see
vm/prepare-image.sh) and ordered ahead of cloud-init-local.service.

That staging is exactly what this test guards, and a unit test cannot: a
disk that is genuinely full makes cloud-init itself fail with ENOSPC while
writing its own bookkeeping, long before it would ever reach a
cloud-init-runcmd-delivered fix, so growth logic living inside the guest
bootstrap cloud-init runs can never rescue the disk that most needs it -
only something baked into the image and run before cloud-init ever touches
disk can. That only shows up across a real reboot of a real, resized disk.
"""

from __future__ import annotations

from agentsandbox.box import Box
from helpers import asbx, current_session, gateway_stats, new_box_name, ssh_run, wait_for_condition, wait_for_console

#: Small enough to grow (and re-clone, for setup) quickly; large enough that
#: growth is unmistakable against filesystem/partition-table overhead.
_GROW_BY_BYTES = 512 * 1024 * 1024


def _start_and_wait(box_name: str):
    """Start an already-created box and wait until it is genuinely usable.

    Mirrors conftest.py's `_boot_box`, minus the `box create` - this test
    reboots the *same* box (create once, start, stop, resize, start again),
    which `_boot_box`/`booted_box`/`fresh_box` have no way to express.
    """
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


def test_disk_growth_survives_a_real_reboot(test_image):
    """Grow a real box's disk file, reboot it, and confirm the guest's own
    partition and filesystem grew to match with no manual step in between -
    the exact thing that failed on a genuinely full disk before
    asbx-growroot.service moved ahead of cloud-init."""
    box_name = new_box_name()
    try:
        asbx("box", "create", box_name, "--image", test_image, "--allow", "api.github.com")
        _start_and_wait(box_name)

        # The baseline has to be the guest's own filesystem size, not the raw
        # disk file's: a filesystem is always smaller than the whole disk
        # (GPT overhead, the EFI system partition), so comparing post-growth
        # guest bytes against the pre-growth *disk file* size would never
        # pass even with perfect growth.
        before = ssh_run(box_name, "findmnt -b -n -o SIZE /")
        assert before.returncode == 0, before.stderr
        original_root_bytes = int(before.stdout.strip())

        disk_bytes = Box.load(box_name).disk_path.stat().st_size
        grown_bytes = disk_bytes + _GROW_BY_BYTES

        asbx("box", "stop", box_name)
        asbx("box", "set", box_name, "--disk-size", str(grown_bytes))
        assert Box.load(box_name).disk_path.stat().st_size == grown_bytes

        _start_and_wait(box_name)

        enabled = ssh_run(box_name, "systemctl is-enabled asbx-growroot.service")
        assert enabled.stdout.strip() == "enabled", (
            f"asbx-growroot.service is not enabled on {test_image}: "
            f"{enabled.stdout!r} {enabled.stderr!r}"
        )

        status = ssh_run(box_name, "systemctl show asbx-growroot.service -p ActiveState,Result --value")
        assert status.returncode == 0, status.stderr
        active_state, unit_result = status.stdout.strip().splitlines()
        assert (active_state, unit_result) == ("active", "success"), (
            f"asbx-growroot.service did not run cleanly on {test_image}: "
            f"ActiveState={active_state} Result={unit_result}\n{status.stderr}"
        )

        after = ssh_run(box_name, "findmnt -b -n -o SIZE /")
        assert after.returncode == 0, after.stderr
        grown_root_bytes = int(after.stdout.strip())
        # Never exactly `_GROW_BY_BYTES` (filesystem metadata overhead grows
        # a little too) - what matters is that it moved, and moved by close
        # to the resize, not that it hit the target byte-for-byte.
        assert grown_root_bytes > original_root_bytes + _GROW_BY_BYTES * 3 // 4, (
            f"root filesystem did not grow on {test_image}: "
            f"was {original_root_bytes}, disk grown by {_GROW_BY_BYTES}, guest now reports {grown_root_bytes}"
        )
    finally:
        asbx("box", "stop", box_name, check=False, timeout=30)
        asbx("box", "rm", box_name, check=False, timeout=30)
