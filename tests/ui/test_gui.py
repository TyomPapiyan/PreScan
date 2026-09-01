"""Headless GUI tests: style, zero QML warnings, no UI freeze, fast cancel."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

import pytest


def test_style_is_fluent_winui3(gui: Any) -> None:
    """The running UI is drawn with the FluentWinUI3 style (§3.3)."""
    from PySide6.QtQuickControls2 import QQuickStyle

    assert QQuickStyle.name() == "FluentWinUI3"


def test_main_qml_loads_with_zero_warnings(gui: Any) -> None:
    """Loading Main.qml must emit no QML warnings/errors (§10.1 wiring is sound)."""
    assert gui.engine.rootObjects(), "Main.qml failed to load"
    assert gui.load_warnings == [], f"QML warnings during load: {gui.load_warnings}"


def test_app_icon_is_multisize(gui: Any) -> None:
    """The window/taskbar icon must load with real sizes (no gear fallback)."""
    from prescan.ui.app import app_icon

    icon = app_icon()
    assert not icon.isNull()
    sizes = {(s.width(), s.height()) for s in icon.availableSizes()}
    assert {(16, 16), (32, 32), (256, 256)} <= sizes


def test_desktop_file_binds_identity() -> None:
    """prescan.desktop must carry the keys that drop 'python3' in the shell."""
    from pathlib import Path

    txt = Path("packaging/prescan.desktop").read_text(encoding="utf-8")
    assert "Name=PreScan" in txt
    assert "Icon=prescan" in txt
    assert "StartupWMClass=prescan" in txt  # X11
    assert "Categories=Utility;Security;" in txt


def test_availability_text_covers_too_large(gui: Any) -> None:
    """The size-limit availability must render a real label, never an empty string."""
    from prescan.core.models import Availability

    text = gui.bridge.availabilityText(Availability.TOO_LARGE.value, "")
    assert text and text != Availability.TOO_LARGE.value


def test_ml_signal_title_shows_percentage(gui: Any) -> None:
    """The ML signal must render its probability as a percentage (DoD M6a)."""
    from prescan.core.models import Severity, Signal, SourceKind

    ml = Signal(
        source="ml",
        kind=SourceKind.ML,
        severity=Severity.HIGH,
        title_key="signal.ml.assessment",
        title_en="ML model: 87% likely malicious",
        data={"probability": 0.87},
    )
    assert "87%" in gui.bridge._signal_title(ml)
    # A non-ML signal keeps its engine-provided English title.
    other = Signal(
        source="clamav",
        kind=SourceKind.LOCAL_ENGINE,
        severity=Severity.CRITICAL,
        title_key="signal.clamav.found",
        title_en="ClamAV detection: X",
    )
    assert gui.bridge._signal_title(other) == "ClamAV detection: X"


def test_dict_list_model_count_is_a_bindable_property(gui: Any) -> None:
    """count must be a Property (empty-state bindings use it, not rowCount())."""
    from prescan.ui.models_qml import DictListModel

    model = DictListModel(["a"])
    seen: list[int] = []
    model.countChanged.connect(lambda: seen.append(model.property("count")))

    assert model.property("count") == 0
    model.replace([{"a": "1"}, {"a": "2"}])
    assert model.property("count") == 2
    model.clear()
    assert model.property("count") == 0
    assert seen == [2, 0]  # signal fired on each change


def _big_sparse_file(path: Path, size: int) -> Path:
    with path.open("wb") as fh:
        fh.truncate(size)
    return path


def test_ui_stays_responsive_and_cancel_is_fast(gui: Any, tmp_path: Path) -> None:
    """The event loop keeps ticking during a large-file scan; cancel stops it <2s."""
    import qasync
    from PySide6.QtCore import QTimer

    bridge = gui.bridge
    bridge._config.allow_network = False  # no cloud lookups in the test

    big = _big_sparse_file(tmp_path / "big.bin", 1024 * 1024 * 1024)  # 1 GiB sparse

    loop = qasync.QEventLoop(gui.app)
    asyncio.set_event_loop(loop)

    ticks = {"n": 0}
    timer = QTimer()
    timer.setInterval(20)
    timer.timeout.connect(lambda: ticks.__setitem__("n", ticks["n"] + 1))
    timer.start()

    async def drive() -> None:
        bridge.scanFile(str(big))
        # Let hashing get under way (runs in a worker thread).
        await asyncio.sleep(0.4)
        assert bridge.busy, "scan should still be running on a 1 GiB file"
        before = ticks["n"]
        await asyncio.sleep(0.3)
        assert ticks["n"] > before, "UI event loop was blocked during the scan"

        # Cancel must take effect in under 2 seconds.
        t0 = time.monotonic()
        bridge.cancel()
        while bridge.busy and time.monotonic() - t0 < 2.0:
            await asyncio.sleep(0.02)
        elapsed = time.monotonic() - t0
        assert not bridge.busy, "scan did not stop"
        assert elapsed < 2.0, f"cancel took {elapsed:.2f}s (>2s)"

    try:
        loop.run_until_complete(drive())
    finally:
        timer.stop()
        loop.close()


@pytest.mark.parametrize(
    ("availability", "expect"),
    [
        ("no_key", "key"),
        ("error", "unavailable"),
        ("offline", "unavailable"),
        ("unsupported_os", "OS"),
    ],
)
def test_availability_text_differs_by_reason(gui: Any, availability: str, expect: str) -> None:
    """NO_KEY / ERROR / UNSUPPORTED_OS map to distinct guidance, not one string."""
    text = gui.bridge.availabilityText(availability, "")
    assert expect.lower() in text.lower()


def test_language_switch_translates_without_restart(gui: Any) -> None:
    """Switching to RU installs the translator and retranslate yields Russian (§9.8)."""
    from PySide6.QtCore import QCoreApplication

    gui.bridge.setLanguage("ru")
    try:
        assert QCoreApplication.translate("ScanPage", "Cancel") == "Отмена"
        assert QCoreApplication.translate("SettingsPage", "Privacy") == "Приватность"
    finally:
        gui.bridge.setLanguage("en")
    assert QCoreApplication.translate("ScanPage", "Cancel") == "Cancel"


def test_privacy_lists_full_url_sources(gui: Any) -> None:
    """The Privacy disclosure names the sources that receive the full URL (§6.2)."""
    sources = gui.bridge.fullUrlSources()
    assert any("VirusTotal" in s for s in sources)
    assert any("urlscan" in s for s in sources)
    assert any("URLhaus" in s for s in sources)
    assert "hash prefix" in gui.bridge.privacyNote().lower()


def _sample_report() -> Any:
    from datetime import UTC, datetime

    from prescan.core.models import (
        FileInfo,
        ScanReport,
        ScanRequest,
        Severity,
        Signal,
        SourceKind,
        TargetKind,
        Verdict,
    )

    now = datetime.now(UTC)
    return ScanReport(
        scan_id="id",
        app_version="0.0.0",
        request=ScanRequest(target_kind=TargetKind.FILE, file_path="/tmp/x.exe"),
        started_at=now,
        finished_at=now,
        duration_s=0.1,
        file=FileInfo(
            path="/tmp/x.exe",
            name="x.exe",
            size=10,
            declared_extension=".exe",
            detected_type="PE32",
            detected_mime="application/x-dosexec",
            md5="0" * 32,
            sha1="0" * 40,
            sha256="a" * 64,
        ),
        signals=[
            Signal(
                source="yara-x",
                kind=SourceKind.LOCAL_ENGINE,
                severity=Severity.HIGH,
                title_key="k",
                title_en="YARA rule matched",
                weight=75,
            )
        ],
        verdict=Verdict.SUSPICIOUS,
        risk_score=60,
        verdict_reason_key="verdict.suspicious",
        verdict_reason_en="Attention required",
    )


def test_save_report_picks_format_by_extension(gui: Any, tmp_path: Path) -> None:
    """Save report… writes a real PDF for a .pdf path and HTML otherwise (§16.1).

    Proves the pdf_export module is actually wired to the Bridge, not dead code:
    a .pdf save must start with the %PDF- signature; a .html save stays HTML.
    """
    gui.bridge._apply_report(_sample_report())

    pdf = tmp_path / "report.pdf"
    assert gui.bridge.saveReport(str(pdf)) is True
    pdf_bytes = pdf.read_bytes()
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 0

    html = tmp_path / "report.html"
    assert gui.bridge.saveReport(str(html)) is True
    html_text = html.read_text(encoding="utf-8")
    assert not html_text.startswith("%PDF-")
    assert "suspicious" in html_text.lower()
