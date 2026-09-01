"""Entry point for the frozen (PyInstaller) build.

The one bundled binary is both the GUI and the CLI: with a command/flag it runs
the Typer CLI (``prescan version|engines|scan|update-model|…``); with no arguments
it launches the GUI (double-click / ``prescan`` on its own). ``python -m prescan``
keeps its own GUI-only entry in ``prescan.__main__`` so the module behaviour and
its test are unchanged.
"""

from __future__ import annotations

import sys


def main() -> int:
    if len(sys.argv) > 1:
        from prescan.cli import app

        app()  # Typer parses sys.argv and raises SystemExit itself
        return 0
    from prescan.ui.app import run

    return run()


if __name__ == "__main__":
    raise SystemExit(main())
