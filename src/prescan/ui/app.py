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

import contextlib
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


def _icons_dir() -> Path:
    """Path to the packaged icons dir (works in dev, wheel and PyInstaller onedir).

    Loaded as package data via importlib.resources, exactly like scoring.py reads
    scoring_weights.toml — no repo-relative or sys._MEIPASS path juggling.
    """
    from importlib import resources

    return Path(str(resources.files("prescan.resources").joinpath("icons")))


def app_icon() -> object:
    """The multi-size window/taskbar icon (the same shield as the in-app mark)."""
    from PySide6.QtGui import QIcon

    icons = _icons_dir()
    icon = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256, 512):
        png = icons / f"prescan_{size}.png"
        if png.exists():
            icon.addFile(str(png))
    if icon.isNull():  # PNGs missing (e.g. not generated): fall back to the SVG
        svg = icons / "prescan.svg"
        if svg.exists():
            icon.addFile(str(svg))
    return icon


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


def _set_app_identity() -> None:
    """Set the process identity *before* the QGuiApplication is constructed.

    Order matters: the Wayland ``app_id`` (matched to ``prescan.desktop`` for the
    dock name + shield icon) and the xdg-desktop-portal app-id registration are both
    taken at startup. Setting the desktop file name only afterwards makes the portal
    reject the change ("connection already associated with an application id") and
    leaves the shell showing the raw app-id with a generic icon. ``StartupWMClass``
    in the desktop file covers the X11/XWayland case.

    On Windows an explicit AppUserModelID is what makes the taskbar use our icon and
    group our windows, instead of falling back to the generic Python/Qt host id.
    """
    from PySide6.QtGui import QGuiApplication

    QGuiApplication.setApplicationName("PreScan")
    QGuiApplication.setApplicationDisplayName("PreScan")
    QGuiApplication.setOrganizationName("PreScan")
    QGuiApplication.setDesktopFileName("prescan")

    if sys.platform == "win32":
        with contextlib.suppress(Exception):  # cosmetic; never block startup on it
            import ctypes

            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("PreScan")


def run() -> int:
    """Launch the PreScan GUI. Blocks until the window is closed."""
    import asyncio

    import qasync
    from PySide6.QtGui import QGuiApplication

    configure_style()
    _set_app_identity()  # must precede QGuiApplication so the app-id is ours from t=0
    app = QGuiApplication(sys.argv)
    app.setWindowIcon(app_icon())  # type: ignore[arg-type]
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
