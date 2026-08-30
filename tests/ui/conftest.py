"""Self-healing guard + shared headless GUI fixture for the UI tests.

The UI tests need PySide6 (the ``ui`` optional group). On a core-only checkout it
is absent, so collection of this directory is skipped — installing the group
flips it on with no code change (a self-healing skip, never a manual flag).

When present, tests run headless via the ``offscreen`` Qt platform. The Bridge is
a process-global QML singleton, so the engine is built once per session and the
QML warnings emitted during that load are captured for the no-warnings test.
"""

from __future__ import annotations

import os
from importlib.util import find_spec
from types import SimpleNamespace
from typing import Any

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

collect_ignore_glob: list[str] = []


def _compile_translations() -> None:
    """Compile .ts -> .qm (a build artifact, git-ignored) so RU tests can load it."""
    import shutil
    import subprocess
    from pathlib import Path

    lrelease = shutil.which("pyside6-lrelease")
    if lrelease is None:  # pragma: no cover - PySide6 always ships it
        return
    i18n = Path(__file__).resolve().parents[2] / "src" / "prescan" / "ui" / "i18n"
    for ts in i18n.glob("*.ts"):
        subprocess.run(
            [lrelease, str(ts), "-qm", str(ts.with_suffix(".qm"))],
            check=False,
            capture_output=True,
        )


if find_spec("PySide6") is None:  # pragma: no cover - core-only checkout
    collect_ignore_glob = ["*.py"]
else:
    import pytest

    @pytest.fixture(scope="session")
    def gui() -> Any:
        """Build the GUI once headlessly, capturing QML warnings during load."""
        from PySide6.QtCore import QtMsgType, qInstallMessageHandler
        from PySide6.QtGui import QGuiApplication

        messages: list[tuple[int, str]] = []

        def handler(mode: QtMsgType, _ctx: object, message: str) -> None:
            messages.append((int(mode), message))

        _compile_translations()
        qInstallMessageHandler(handler)
        app = QGuiApplication.instance() or QGuiApplication([])

        from prescan.ui.app import build_engine

        engine, bridge = build_engine()
        load_warnings = [
            m
            for mode, m in messages
            if mode
            in (
                int(QtMsgType.QtWarningMsg),
                int(QtMsgType.QtCriticalMsg),
                int(QtMsgType.QtFatalMsg),
            )
        ]
        yield SimpleNamespace(app=app, engine=engine, bridge=bridge, load_warnings=load_warnings)
        qInstallMessageHandler(None)
