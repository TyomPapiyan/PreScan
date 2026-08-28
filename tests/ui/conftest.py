"""Self-healing guard for the UI test package.

The UI tests need a Qt binding (PySide6, brought in by the ``ui`` optional
group together with pytest-qt). Neither is in the ``dev`` group, so on a
core-only checkout they are absent.

Rather than a manual opt-out flag that must be remembered and removed later
(a silent trap if forgotten), collection of this directory is skipped whenever
PySide6 cannot be imported. Installing the ``ui`` group flips this on by itself
— no code change required.

``collect_ignore_glob`` is used instead of a module-level ``pytest.skip`` because
raising Skip during conftest import is an error in pytest, not a skip.
"""

from __future__ import annotations

from importlib.util import find_spec

collect_ignore_glob: list[str] = []

if find_spec("PySide6") is None:
    # No Qt binding available: ignore every test module in tests/ui/.
    collect_ignore_glob = ["*.py"]
