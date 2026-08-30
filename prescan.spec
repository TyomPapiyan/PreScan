# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for PreScan (GUI).

The bundled application launches the GUI: the entry script is the package
``__main__`` (which calls ``prescan.ui.app.run``), matching ``python -m prescan``.
The CLI stays available as the separate ``prescan`` console script.

Filled out fully on M7 (--onedir; bundle ui/vendor/RinUI, resources/, qml/,
i18n .qm and the licenses/ folder). --onefile is forbidden (§11.3).
"""

# GUI entry point for the bundle.
ENTRY_SCRIPT = "src/prescan/__main__.py"

# TODO(M7): Analysis(ENTRY_SCRIPT, ...) / PYZ / EXE(console=False) / COLLECT
# for a --onedir build, datas for qml/i18n/resources/vendor/licenses.
