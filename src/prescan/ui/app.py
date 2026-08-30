"""GUI entry point: QApplication + qasync event loop.

The Fluent/WinUI 3 style is selected explicitly in code with
``QQuickStyle.setStyle`` before any Controls load (§3.3) — not via an
environment variable, which a desktop theme could already have set to something
else. The Bridge is exposed to QML as a **singleton** (``import PreScan``); a
singleton is resolved before the QML loads, so bindings never transiently see a
null object the way context properties can.

RinUI is vendored under ``ui/vendor/RinUI`` (§11.2) but the running UI uses the
FluentWinUI3 base with local components — the §3.3 fallback; RinUI adoption is a
post-M7 task.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from PySide6.QtQml import QQmlApplicationEngine

    from prescan.ui.bridge import Bridge

_UI_DIR = Path(__file__).resolve().parent
_QML_DIR = _UI_DIR / "qml"
_I18N_DIR = _UI_DIR / "i18n"
_STYLE = "FluentWinUI3"

_translator: object | None = None


def apply_language(engine: QQmlApplicationEngine, code: str) -> None:
    """Install/remove the QTranslator for ``code`` and retranslate live (§9.8)."""
    from PySide6.QtCore import QCoreApplication, QTranslator

    global _translator
    app = QCoreApplication.instance()
    if app is None:  # pragma: no cover - app always exists when UI runs
        return
    if _translator is not None:
        app.removeTranslator(_translator)  # type: ignore[arg-type]
        _translator = None
    qm = _I18N_DIR / f"prescan_{code}.qm"
    if code not in ("en", "system") and qm.exists():
        translator = QTranslator()
        if translator.load(str(qm)):
            app.installTranslator(translator)
            _translator = translator
    engine.retranslate()


def configure_style() -> None:
    """Select the Fluent/WinUI 3 base style before any Controls are loaded."""
    from PySide6.QtQuickControls2 import QQuickStyle

    QQuickStyle.setStyle(_STYLE)
    os.environ.setdefault("QT_QUICK_CONTROLS_STYLE", _STYLE)  # fallback only


def build_engine() -> tuple[QQmlApplicationEngine, Bridge]:
    """Create the QML engine with the Bridge singleton and load Main.qml.

    Separated from run() so tests drive the same wiring headlessly. Requires a
    QGuiApplication to already exist.
    """
    from PySide6.QtQml import QQmlApplicationEngine, qmlRegisterSingletonInstance

    from prescan.ui.bridge import Bridge

    configure_style()
    bridge = Bridge()
    # PySide6's stub types the QML type name as bytes, but the runtime wants str.
    qmlRegisterSingletonInstance(Bridge, "PreScan", 1, 0, "Bridge", bridge)  # type: ignore[arg-type]

    engine = QQmlApplicationEngine()
    engine.addImportPath(str(_QML_DIR))
    engine.load(str(_QML_DIR / "Main.qml"))

    # Live language switching (§9.8): re-install the translator and retranslate.
    bridge.languageChanged.connect(lambda: apply_language(engine, bridge.current_language()))
    apply_language(engine, bridge.current_language())
    return engine, bridge


def run() -> int:
    """Launch the PreScan GUI. Blocks until the window is closed."""
    import asyncio

    import qasync
    from PySide6.QtGui import QGuiApplication

    configure_style()
    app = QGuiApplication(sys.argv)
    app.setApplicationName("PreScan")
    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)

    engine, bridge = build_engine()
    if not engine.rootObjects():
        return 1
    # Populate engine statuses once the loop is actually running.
    loop.call_soon(bridge.refreshEngines)

    with loop:
        loop.run_forever()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(run())
