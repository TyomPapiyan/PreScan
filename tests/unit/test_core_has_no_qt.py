"""§10.1 guard: importing the whole engine core must not pull in Qt.

The engine must run on a machine without Qt installed. This test imports every
``prescan.core.*`` module and fails if ``PySide6`` (or ``qasync``) appears in
``sys.modules`` as a result.
"""

from __future__ import annotations

import importlib
import pkgutil
import sys

import prescan.core

BANNED = ("PySide6", "qasync")


def _core_module_names() -> list[str]:
    """Return the dotted names of every module under ``prescan.core``."""
    names: list[str] = []
    for info in pkgutil.walk_packages(prescan.core.__path__, prefix="prescan.core."):
        names.append(info.name)
    return names


def test_core_imports_pull_in_no_qt() -> None:
    """Importing all of ``prescan.core.*`` must not load Qt."""
    for name in _core_module_names():
        importlib.import_module(name)

    leaked = [mod for mod in BANNED if mod in sys.modules]
    assert not leaked, f"core/ pulled in banned Qt modules: {leaked}"
