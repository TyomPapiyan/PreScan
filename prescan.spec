# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for PreScan (GUI), --onedir only (§11.3: --onefile forbidden).

The bundled app launches the GUI: the entry script is the package ``__main__``
(which calls ``prescan.ui.app.run``), matching ``python -m prescan``. The CLI is
the same frozen binary via ``prescan <command>``.

Bundled data: the QML tree, compiled ``.qm`` translations, package ``resources/``
(icons, report template, scoring weights), ``ui/assets``, the vendored RinUI, and
the whole ``licenses/`` folder next to the executable (§11.2). Qt libraries are
kept as separate, replaceable files by --onedir (LGPL §4d, §11.2 row 4) -- never
packed into one file. The Windows executable and its shortcuts use ``prescan.ico``.

Compile the ``.qm`` files before building:
    pyside6-lrelease src/prescan/ui/i18n/prescan_ru.ts -qm src/prescan/ui/i18n/prescan_ru.qm
    pyside6-lrelease src/prescan/ui/i18n/prescan_en.ts -qm src/prescan/ui/i18n/prescan_en.qm
"""

ENTRY_SCRIPT = "packaging/pyinstaller_entry.py"
ICON = "src/prescan/resources/icons/prescan.ico"

# The automatic PySide6 hook collects every Qt module it can; exclude the big ones
# the app never touches (WebEngine alone is ~300 MB) so the bundle is a few hundred
# MB, not ~1 GB. Kept: Core/Gui/Widgets/Qml/Quick/QuickControls2/Svg/Network/DBus.
_QT_EXCLUDES = [
    "PySide6.QtWebEngineCore", "PySide6.QtWebEngineQuick", "PySide6.QtWebEngineWidgets",
    "PySide6.QtWebView", "PySide6.QtWebSockets", "PySide6.QtWebChannel",
    "PySide6.QtQuick3D", "PySide6.Qt3DCore", "PySide6.Qt3DRender", "PySide6.Qt3DInput",
    "PySide6.Qt3DAnimation", "PySide6.Qt3DExtras", "PySide6.Qt3DLogic",
    "PySide6.QtMultimedia", "PySide6.QtMultimediaWidgets", "PySide6.QtSpatialAudio",
    "PySide6.QtCharts", "PySide6.QtDataVisualization", "PySide6.QtGraphs",
    "PySide6.QtPdf", "PySide6.QtPdfWidgets", "PySide6.QtDesigner", "PySide6.QtUiTools",
    "PySide6.QtRemoteObjects", "PySide6.QtScxml", "PySide6.QtTextToSpeech",
    "PySide6.QtSensors", "PySide6.QtNfc", "PySide6.QtBluetooth", "PySide6.QtSerialPort",
    "PySide6.QtSerialBus", "PySide6.QtLocation", "PySide6.QtPositioning",
    "PySide6.QtSql", "PySide6.QtTest", "PySide6.QtHelp", "PySide6.QtNetworkAuth",
    "PySide6.QtHttpServer", "PySide6.QtQuickWidgets",
]

# Data shipped inside the bundle (src dir -> dest dir relative to the app root).
datas = [
    ("src/prescan/resources", "prescan/resources"),
    ("src/prescan/ui/qml", "prescan/ui/qml"),
    ("src/prescan/ui/i18n", "prescan/ui/i18n"),
    ("src/prescan/ui/assets", "prescan/ui/assets"),
    ("src/prescan/ui/vendor/RinUI", "prescan/ui/vendor/RinUI"),
    ("licenses", "licenses"),
]
# The automatic PySide6 hook collects the Qt libs, plugins and QML modules it needs
# (including the QtQuick Controls / FluentWinUI3 style loaded at runtime).
a = Analysis(
    [ENTRY_SCRIPT],
    pathex=["src"],
    binaries=[],
    datas=datas,
    hiddenimports=["prescan.ui.app", "prescan.cli"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter", "matplotlib", "lightgbm", "onnxmltools", "sklearn", "thrember",
        "pandas", "scipy", "IPython",
        *_QT_EXCLUDES,
    ],
    noarchive=False,
)

# The PySide6 hook still copies whole Qt module libs and their QML plugins even
# when the Python modules are excluded; drop the unused ones from the final lists so
# they don't ship (Qt3D, WebEngine, Multimedia, … — the app never loads them).
_DROP = (
    "Qt63D", "Qt6Quick3D", "Qt6Multimedia", "Qt6SpatialAudio", "Qt6Charts",
    "Qt6DataVisualization", "Qt6Graphs", "Qt6Pdf", "Qt6WebEngine", "Qt6WebView",
    "Qt6WebSockets", "Qt6WebChannel", "Qt6Designer", "Qt6RemoteObjects", "Qt6Scxml",
    "Qt6TextToSpeech", "Qt6Sensors", "Qt6Nfc", "Qt6Bluetooth", "Qt6SerialPort",
    "Qt6SerialBus", "Qt6Location", "Qt6Positioning", "Qt6Sql", "Qt6Test", "Qt6Help",
    "Qt6NetworkAuth", "Qt6HttpServer", "Qt6UiTools", "Qt6QuickWidgets",
)
_DROP_QML = ("/Qt3D", "/QtQuick3D", "/QtMultimedia", "/QtWebEngine", "/QtCharts",
             "/QtDataVisualization", "/QtWebView", "/QtBluetooth", "/QtPositioning")


def _drop(entry):
    name = entry[0].replace("\\", "/")
    return any(d in name for d in _DROP) or any(q in name for q in _DROP_QML)


a.binaries = [b for b in a.binaries if not _drop(b)]
a.datas = [d for d in a.datas if not _drop(d)]

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,  # --onedir: binaries live beside the exe, not inside it
    name="prescan",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,  # GUI app: no console window on Windows
    icon=ICON,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="PreScan",
)
