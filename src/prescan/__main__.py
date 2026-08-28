"""``python -m prescan`` entry point.

On M5 this will launch the GUI (``prescan.ui.app``). Until the UI layer exists
it defers to the CLI, so the module stays runnable without Qt installed (§10.1).
"""

from __future__ import annotations

from prescan.cli import app


def main() -> None:
    """Run PreScan. Delegates to the CLI until the GUI lands on M5."""
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
