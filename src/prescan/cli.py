"""PreScan command-line interface.

This is a first-class public interface, not just a test harness (spec §14.1).
On M0 only ``prescan version`` is wired up; the remaining commands are declared
as placeholders and filled in on later milestones.
"""

from __future__ import annotations

import typer

from prescan import __version__

app = typer.Typer(
    name="prescan",
    help="Pre-execution malware and link scanner.",
    no_args_is_help=True,
    add_completion=False,
)


@app.callback()
def main() -> None:
    """PreScan: check a file before you run it, and a link before you download it."""
    # Force Typer into multi-command mode so subcommands like ``version`` and the
    # ``scan``/``engines``/... commands (added on later milestones) are addressable.


@app.command()
def version() -> None:
    """Print the PreScan version and exit."""
    typer.echo(f"PreScan {__version__}")


if __name__ == "__main__":  # pragma: no cover
    app()
