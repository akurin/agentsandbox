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


def _write_golden_meta(content: str) -> None:
    from agentsandbox.vm.vfkit import default_golden_image

    path = default_golden_image().with_name("golden.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def test_doctor_reports_which_distro_the_base_image_is():
    """One golden image backs every environment, so the distro is a property
    of the host - otherwise only answerable by booting a guest."""
    _write_golden_meta(
        '{"distro": "ubuntu", "built_at": "2026-08-05T09:00:00Z", "prepared": true}'
    )
    assert "ubuntu" in cli._golden_description()
    assert "not prepared" not in cli._golden_description()


def test_an_unprepared_image_is_called_out():
    """An unprepared image boots fine and then fails at the tunnel, with
    nothing on the console explaining why."""
    _write_golden_meta('{"distro": "debian", "built_at": "x", "prepared": false}')
    assert "not prepared" in cli._golden_description()


def test_a_missing_or_broken_record_does_not_guess():
    assert "unknown" in cli._golden_description()
    _write_golden_meta("{not json")
    assert "unreadable" in cli._golden_description()
