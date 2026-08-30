"""§10.1 guard: importing the whole engine core must not pull in Qt.

The engine must run on a machine without Qt installed. This runs in a *clean
subprocess* so the check is independent of test order — other tests in the same
session (the UI tests) legitimately import PySide6, which would otherwise appear
in this process's ``sys.modules``.
"""

from __future__ import annotations

import subprocess
import sys

_PROBE = """
import importlib, pkgutil, sys
import prescan.core
for info in pkgutil.walk_packages(prescan.core.__path__, prefix="prescan.core."):
    importlib.import_module(info.name)
leaked = [m for m in ("PySide6", "qasync") if m in sys.modules]
if leaked:
    raise SystemExit("core pulled in banned Qt modules: " + repr(leaked))
"""


def test_core_imports_pull_in_no_qt() -> None:
    """Importing all of ``prescan.core.*`` in a fresh interpreter loads no Qt."""
    result = subprocess.run(
        [sys.executable, "-c", _PROBE],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
