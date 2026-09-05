"""Stage E: the after-the-scan cloud-upload offer, its consent modal, and the
re-enabled Settings toggle.

Structural tests read the QML source (a warnings test cannot catch a wrong default
button or a pre-ticked toggle); behavioural tests drive the Bridge. Nothing here
touches the network: the upload path is exercised with fake providers.
"""

from __future__ import annotations

import asyncio
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from prescan.core.models import (
    Availability,
    FileInfo,
    ScanReport,
    ScanRequest,
    Severity,
    Signal,
    SourceKind,
    TargetKind,
    UploadOutcome,
    Verdict,
)
from prescan.core.providers import upload_provider_name

_QML = Path(__file__).resolve().parents[2] / "src" / "prescan" / "ui" / "qml" / "pages"
_SERVICE = upload_provider_name()


# --------------------------------------------------------------------------- #
# Source helpers (brace-matched block extraction)
# --------------------------------------------------------------------------- #
def _blocks(type_name: str, qml: str) -> list[str]:
    """Return each top-level ``TypeName { ... }`` block, brace-matched."""
    blocks: list[str] = []
    for match in re.finditer(rf"(?<![A-Za-z]){re.escape(type_name)}\s*\{{", qml):
        depth, k = 0, qml.index("{", match.start())
        while k < len(qml):
            depth += 1 if qml[k] == "{" else -1 if qml[k] == "}" else 0
            if depth == 0:
                break
            k += 1
        blocks.append(qml[match.start() : k + 1])
    return blocks


def _cloud_dialog() -> str:
    text = (_QML / "ScanPage.qml").read_text(encoding="utf-8")
    for block in _blocks("Dialog", text):
        if 'objectName: "cloudUploadDialog"' in block:
            return block
    raise AssertionError("cloudUploadDialog not found in ScanPage.qml")


def _sets_own_width(block: str) -> bool:
    """True if ``width:`` is a direct property of the block (brace-depth 1)."""
    depth = 0
    for match in re.finditer(r"\{|\}|(?<![A-Za-z.])width\s*:", block):
        token = match.group()
        if token == "{":
            depth += 1
        elif token == "}":
            depth -= 1
        elif depth == 1:
            return True
    return False


# --------------------------------------------------------------------------- #
# Structural tests (points 20-23)
# --------------------------------------------------------------------------- #
def test_dialog_default_button_is_cancel() -> None:
    """Point 20: the focused (default) button is Cancel, never the send action.

    Read from markup: the Button that carries ``focus: true`` must be the RejectRole
    (Cancel) one, and the AcceptRole (send) button must not be focused -- so Enter and
    Esc both cancel and a stray keypress never uploads.
    """
    dialog = _cloud_dialog()
    buttons = _blocks("Button", dialog)
    reject = [b for b in buttons if "RejectRole" in b]
    accept = [b for b in buttons if "AcceptRole" in b]
    assert len(reject) == 1 and len(accept) == 1, "expected one accept and one reject button"
    assert "focus: true" in reject[0] and "Cancel" in reject[0]
    assert "focus: true" not in accept[0]
    assert dialog.count("focus: true") == 1  # exactly one focused button


def test_dialog_has_explicit_width() -> None:
    """Point 21: the consent Dialog sets its own width (guards the binding loop)."""
    assert _sets_own_width(_cloud_dialog()), "cloudUploadDialog does not set its own width"


def test_dialog_has_no_pre_checked_toggles() -> None:
    """Point 22: consent is a deliberate button press -- no pre-ticked toggles."""
    dialog = _cloud_dialog()
    assert "checked: true" not in dialog
    assert not _blocks("CheckBox", dialog)
    assert not _blocks("Switch", dialog)


def test_never_upload_toggle_is_live_and_note_is_gone() -> None:
    """Point 23: the 'Never upload' toggle is enabled and wired; inert note removed."""
    text = (_QML / "SettingsPage.qml").read_text(encoding="utf-8")
    checkboxes = [b for b in _blocks("CheckBox", text) if "Never upload files to the cloud" in b]
    assert len(checkboxes) == 1, "the 'Never upload' CheckBox should appear exactly once"
    box = checkboxes[0]
    assert "enabled: false" not in box, "the toggle must no longer be disabled"
    assert "Bridge.setNeverUpload(checked)" in box, "the toggle must call setNeverUpload"
    # The old inert explanation must be gone from the page.
    assert "not available in this version" not in text
    assert "not implemented" not in text


def test_dialog_shows_what_leaves_and_does_not_soften() -> None:
    """Points 13-15: the modal shows name/size/SHA-256/service and the full disclosure."""
    dialog = _cloud_dialog()
    for field in ("uploadFileName", "uploadFileSize", "uploadFileSha256", "uploadService"):
        assert f"Bridge.{field}" in dialog, f"the dialog must show {field}"
    assert "cannot be recalled" in dialog  # the file cannot be withdrawn
    assert "premium" in dialog and "community" in dialog  # VT disclosure, unsoftened
    assert "already left your machine" in dialog  # cancel-after-send is spelled out


# --------------------------------------------------------------------------- #
# Behavioural helpers
# --------------------------------------------------------------------------- #
def _file_report(
    tmp_path: Path,
    *,
    verdict: Verdict,
    signals: list[Signal] | None = None,
    uploaded_to: str | None = None,
) -> ScanReport:
    f = tmp_path / "sample.bin"
    f.write_bytes(b"data")
    now = datetime.now(UTC)
    return ScanReport(
        scan_id="id",
        app_version="0.0.0",
        request=ScanRequest(target_kind=TargetKind.FILE, file_path=f),
        started_at=now,
        finished_at=now,
        duration_s=0.1,
        file=FileInfo(
            path=f,
            name="sample.bin",
            size=4,
            declared_extension=".bin",
            detected_type="data",
            detected_mime="application/octet-stream",
            md5="0" * 32,
            sha1="0" * 40,
            sha256="a" * 64,
        ),
        signals=signals or [],
        verdict=verdict,
        risk_score=0 if verdict is Verdict.SAFE else 50,
        verdict_reason_key="k",
        verdict_reason_en="reason",
        uploaded_to=uploaded_to,
    )


# --------------------------------------------------------------------------- #
# Behavioural tests (points 24-25)
# --------------------------------------------------------------------------- #
def test_offer_hidden_when_dangerous_or_known(gui: Any, tmp_path: Path) -> None:
    """Point 24: no offer when the verdict is DANGEROUS or the file is cloud-known."""
    bridge = gui.bridge
    bridge._config.allow_network = True
    try:
        bridge._apply_report(_file_report(tmp_path, verdict=Verdict.DANGEROUS))
        assert bridge.canOfferUpload is False  # decided; no point uploading

        known = Signal(
            source=_SERVICE,  # the upload provider already knows this file
            kind=SourceKind.CLOUD_REPUTATION,
            severity=Severity.INFO,
            title_key="k",
            title_en="known",
        )
        bridge._apply_report(_file_report(tmp_path, verdict=Verdict.SUSPICIOUS, signals=[known]))
        assert bridge.canOfferUpload is False  # already known to the cloud

        # Unknown + not dangerous -> the offer is available.
        bridge._apply_report(_file_report(tmp_path, verdict=Verdict.SUSPICIOUS))
        assert bridge.canOfferUpload is True
    finally:
        bridge._apply_report(_file_report(tmp_path, verdict=Verdict.SAFE, uploaded_to=_SERVICE))


def test_offer_hidden_when_network_off(gui: Any, tmp_path: Path) -> None:
    """No offer with the network off: nothing could be uploaded anyway."""
    bridge = gui.bridge
    bridge._config.allow_network = False
    try:
        bridge._apply_report(_file_report(tmp_path, verdict=Verdict.SUSPICIOUS))
        assert bridge.canOfferUpload is False
    finally:
        bridge._config.allow_network = True


def test_lock_disables_the_offer_and_names_the_setting(gui: Any, tmp_path: Path) -> None:
    """Point 25: with the lock on, the button is disabled and the setting is named.

    ``uploadLocked`` drives ``enabled: !Bridge.uploadLocked`` in the markup, and the
    note next to it names the exact setting to turn off.
    """
    bridge = gui.bridge
    original = bridge._config.never_upload_files
    bridge._config.never_upload_files = True
    try:
        assert bridge.uploadLocked is True
        dialog_owner = (_QML / "ScanPage.qml").read_text(encoding="utf-8")
        assert "enabled: !Bridge.uploadLocked" in dialog_owner
        assert "Never upload files to the cloud" in dialog_owner  # the named setting
    finally:
        bridge._config.never_upload_files = original


def test_upload_slot_reruns_with_consent(gui: Any, tmp_path: Path, monkeypatch: Any) -> None:
    """The slot re-runs the whole scan with allow_cloud_upload=True (points 8-10)."""
    bridge = gui.bridge
    bridge._config.allow_network = True
    bridge._config.never_upload_files = False
    started: list[ScanRequest] = []
    monkeypatch.setattr(bridge, "_start", lambda req: started.append(req))
    try:
        bridge._apply_report(_file_report(tmp_path, verdict=Verdict.SUSPICIOUS))
        assert bridge.canOfferUpload is True
        bridge.uploadCurrentToCloud()
        assert len(started) == 1
        assert started[0].allow_cloud_upload is True
        assert started[0].target_kind is TargetKind.FILE
    finally:
        bridge._apply_report(_file_report(tmp_path, verdict=Verdict.SAFE, uploaded_to=_SERVICE))


# --------------------------------------------------------------------------- #
# Non-blocking upload path (point 26) -- fake providers, no network (point 27)
# --------------------------------------------------------------------------- #
class _FakeHash:
    name = _SERVICE
    kind = SourceKind.CLOUD_REPUTATION
    stage_id = "reputation"
    requires_key = True

    async def availability(self) -> tuple[Availability, str]:
        return Availability.READY, "ready"

    async def lookup_hash(self, sha256: str) -> list[Signal]:
        return []  # file unknown to the cloud, so the gate proceeds to upload


class _FakeUpload:
    name = _SERVICE
    supports_upload = True
    max_upload_bytes = 1_000_000

    async def availability(self) -> tuple[Availability, str]:
        return Availability.READY, "ready"

    async def upload_file(self, path: Path, *, cancel: Any = None) -> UploadOutcome:
        # Slow but cooperative: yield to the loop each tick and stop on cancel, so the
        # UI stays responsive and cancel is prompt -- all without touching the network.
        for _ in range(2000):
            if cancel is not None and cancel.is_set():
                break
            await asyncio.sleep(0.02)
        return UploadOutcome(
            sent=True, sent_at=datetime.now(UTC), availability=Availability.READY, signals=[]
        )


def test_ui_stays_responsive_during_upload_and_cancel_is_fast(
    gui: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    """Point 26: the event loop keeps ticking during a cloud upload; cancel stops it.

    The upload is faked (point 27: no network). The whole scan runs with consent; the
    slow part is the upload, so this proves stage 13 does not block the UI thread.
    """
    import qasync
    from PySide6.QtCore import QTimer

    from prescan.core import pipeline as pipeline_mod

    bridge = gui.bridge
    bridge._config.allow_network = True
    bridge._config.never_upload_files = False

    async def _no_engines(self: Any, *a: object, **k: object) -> tuple[list[Signal], bool]:
        return [], False

    monkeypatch.setattr(pipeline_mod.Pipeline, "_run_engines", _no_engines)
    monkeypatch.setattr(pipeline_mod, "build_hash_providers", lambda *a, **k: [_FakeHash()])
    monkeypatch.setattr(pipeline_mod, "build_upload_provider", lambda *a, **k: _FakeUpload())

    f = tmp_path / "consented.bin"
    f.write_bytes(b"data")
    request = ScanRequest(
        target_kind=TargetKind.FILE, file_path=f, allow_cloud_upload=True, allow_network=True
    )

    loop = qasync.QEventLoop(gui.app)
    asyncio.set_event_loop(loop)
    ticks = {"n": 0}
    timer = QTimer()
    timer.setInterval(20)
    timer.timeout.connect(lambda: ticks.__setitem__("n", ticks["n"] + 1))
    timer.start()

    async def drive() -> None:
        bridge._start(request)
        await asyncio.sleep(0.3)
        assert bridge.busy, "the upload scan should still be running"
        before = ticks["n"]
        await asyncio.sleep(0.3)
        assert ticks["n"] > before, "UI event loop was blocked during the upload"

        t0 = time.monotonic()
        bridge.cancel()
        while bridge.busy and time.monotonic() - t0 < 2.0:
            await asyncio.sleep(0.02)
        assert not bridge.busy, "upload scan did not stop on cancel"
        assert time.monotonic() - t0 < 2.0, "cancel took too long"

    try:
        loop.run_until_complete(drive())
    finally:
        timer.stop()
        loop.close()
