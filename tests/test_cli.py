"""The argument parser itself.

Not the commands' behaviour - that lives with the subsystems they drive -
but the surface: what is reachable, and what a user can discover from
`asbx --help`.
"""

from __future__ import annotations

import argparse

from agentsandbox import cli

def test_every_command_appears_in_the_usage_line():
    """The usage line used to be a hand-written string.

    `asbx set` shipped working but invisible: it was registered, and nothing
    listed it, so the only way to discover it was to read the source. Deriving
    the line from the registered parsers is what stops that recurring - this
    test guards the derivation.
    """
    parser = cli.build_parser()
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))

    listed = set(sub.metavar.strip("{}").split(","))
    registered = set(sub.choices)

    assert listed <= registered, f"usage line names commands that do not exist: {listed - registered}"
    missing = registered - listed - {"vsock-proxy"}
    assert not missing, f"registered but not in the usage line: {missing}"


def test_hidden_commands_stay_out_of_help_entirely():
    """help=SUPPRESS alone leaves a literal '==SUPPRESS==' in the output."""
    parser = cli.build_parser()
    assert "vsock-proxy" in parser._actions[-1].choices  # still callable
    assert "SUPPRESS" not in parser.format_help()
    assert "vsock-proxy" not in parser.format_help()


def test_set_is_reachable_and_wired_up():
    args = cli.build_parser().parse_args(["set", "neo", "--memory", "8192"])
    assert args.func is cli.cmd_env_set
    assert args.name == "neo"
    assert args.memory == 8192


def _build_image(name: str, distro: str, *, prepared: bool = True) -> None:
    """Stand in for ./vm/build-image.sh: a named raw file plus its metadata."""
    import json

    from agentsandbox.vm.vfkit import image_metadata_path, image_path

    image_path(name).write_bytes(b"not a real disk")
    image_metadata_path(name).write_text(
        json.dumps({"name": name, "distro": distro, "prepared": prepared})
    )


def test_doctor_lists_every_built_image_with_its_distro():
    """Which distro is in play is a property of the image an environment
    names, so doctor lists what exists rather than asserting one answer."""
    _build_image("ubuntu-24.04", "ubuntu")
    described = " ".join(cli._describe_images())
    assert "debian-13" in described and "debian" in described
    assert "ubuntu-24.04" in described and "ubuntu" in described


def test_an_unprepared_image_is_called_out():
    """An unprepared image boots fine and then fails at the tunnel, with
    nothing on the console explaining why."""
    _build_image("ubuntu-24.04", "ubuntu", prepared=False)
    described = [line for line in cli._describe_images() if "ubuntu" in line]
    assert "not prepared" in described[0]


def test_doctor_says_so_when_nothing_is_built():
    from agentsandbox.vm.vfkit import DEFAULT_IMAGE, image_path

    image_path(DEFAULT_IMAGE).unlink()
    assert "none built" in cli._describe_images()[0]


def test_an_environment_records_the_image_it_was_created_with():
    """The point of the whole thing: `asbx reset` must rebuild from the image
    the environment was created with, not from whatever was built last."""
    from agentsandbox.env import Environment

    _build_image("ubuntu-24.04", "ubuntu")
    assert cli.main(["create", "on-ubuntu", "--image", "ubuntu-24.04"]) == 0
    assert Environment.load("on-ubuntu").image == "ubuntu-24.04"

    # Building another image later must not move it.
    _build_image("debian-14", "debian")
    assert Environment.load("on-ubuntu").image == "ubuntu-24.04"


def test_two_environments_can_run_different_images():
    from agentsandbox.env import Environment

    _build_image("ubuntu-24.04", "ubuntu")
    assert cli.main(["create", "env-deb"]) == 0
    assert cli.main(["create", "env-ubu", "--image", "ubuntu-24.04"]) == 0
    assert Environment.load("env-deb").image == "debian-13"
    assert Environment.load("env-ubu").image == "ubuntu-24.04"


def test_creating_on_an_image_that_does_not_exist_is_refused():
    """Otherwise it looks fine until the first start, which fails in vfkit."""
    assert cli.main(["create", "doomed", "--image", "no-such-image"]) == cli.EXIT_USAGE
    from agentsandbox.env import Environment

    assert not Environment.exists("doomed")


def test_an_environment_created_before_images_were_named_still_starts(asbx_home):
    """Hosts built earlier have an unnamed images/golden.raw and environments
    with no image field. Both must keep working."""
    from agentsandbox.env import Environment
    from agentsandbox.vm.vfkit import DEFAULT_IMAGE, image_path, resolve_image

    image_path(DEFAULT_IMAGE).unlink()
    legacy = asbx_home / "images" / "golden.raw"
    legacy.write_bytes(b"not a real disk")

    env = Environment.from_dict({"name": "old"})  # no image key at all
    assert env.image == DEFAULT_IMAGE
    assert resolve_image(env.image) == legacy
