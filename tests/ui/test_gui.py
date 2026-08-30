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


def test_privacy_lists_full_url_sources(gui: Any) -> None:
    """The Privacy disclosure names the sources that receive the full URL (§6.2)."""
    sources = gui.bridge.fullUrlSources()
    assert any("VirusTotal" in s for s in sources)
    assert any("urlscan" in s for s in sources)
    assert any("URLhaus" in s for s in sources)
    assert "hash prefix" in gui.bridge.privacyNote().lower()
