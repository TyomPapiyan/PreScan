"""``python -m prescan`` entry point → the GUI (spec §4).

The console script ``prescan`` (pyproject [project.scripts]) is the CLI; the
module entry point launches the graphical app.
"""

from __future__ import annotations


def main() -> int:
    """Launch the PreScan GUI."""
    from prescan.ui.app import run

    return run()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
