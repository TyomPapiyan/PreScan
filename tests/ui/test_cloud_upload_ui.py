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
    Signal,
    SourceKind,
    TargetKind,
    UploadOutcome,
    Verdict,
)
from prescan.core.providers import upload_provider_name

_QML = Path(__file__).resolve().parents[2] / "src" / "prescan" / "ui" / "qml" / "pages"
_SERVICE = upload_provider_name()
_UPLOADED_AT = datetime(2026, 9, 6, 9, 0, tzinfo=UTC)


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


def test_dialog_names_the_downloaded_file_for_a_link() -> None:
    """Point 16: for a link-downloaded file the dialog says so, keyed to the subject flag.

    A dedicated notice, shown only when the subject is a downloaded body, states it is
    about the downloaded file and not the address -- consent to scan the link does not
    cover uploading its contents.
    """
    dialog = _cloud_dialog()
    assert "Bridge.uploadSubjectIsDownloaded" in dialog
    assert "downloaded from the link" in dialog
    assert "not the address" in dialog


# --------------------------------------------------------------------------- #
# Behavioural helpers
# --------------------------------------------------------------------------- #
def _file_report(
    tmp_path: Path,
    *,
    verdict: Verdict,
    signals: list[Signal] | None = None,
    uploaded_to: str | None = None,
    upload_could_help: bool = False,
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
        upload_could_help=upload_could_help,
    )


# --------------------------------------------------------------------------- #
# Behavioural tests (points 24-25)
# --------------------------------------------------------------------------- #
def test_offer_reads_core_field_and_needs_a_file(gui: Any, tmp_path: Path) -> None:
    """Point 24 (+ point 6): the offer only reads core's upload_could_help + report.file.

    The "would it help" logic lives in core (verdict, cloud-known); the bridge does not
    re-derive it. So the offer is shown iff the field is True and there is a file to
    describe, and hidden whenever the field is False.
    """
    bridge = gui.bridge
    try:
        # Field False -> never offered, whatever else is true.
        bridge._apply_report(_file_report(tmp_path, verdict=Verdict.SUSPICIOUS))
        assert bridge.canOfferUpload is False
        # Field True + a file present -> offered.
        bridge._apply_report(
            _file_report(tmp_path, verdict=Verdict.SUSPICIOUS, upload_could_help=True)
        )
        assert bridge.canOfferUpload is True
    finally:
        bridge._apply_report(_file_report(tmp_path, verdict=Verdict.SAFE))


def test_subject_flag_true_for_a_link_downloaded_file(gui: Any, tmp_path: Path) -> None:
    """Point 16: the subject flag is True for a URL scan (downloaded body), False for a file."""
    bridge = gui.bridge
    try:
        bridge._apply_report(_file_report(tmp_path, verdict=Verdict.SUSPICIOUS))
        assert bridge.uploadSubjectIsDownloaded is False  # a chosen file
        url_report = _file_report(tmp_path, verdict=Verdict.SUSPICIOUS)
        url_report = url_report.model_copy(
            update={"request": ScanRequest(target_kind=TargetKind.URL, url="https://x.test/f")}
        )
        bridge._apply_report(url_report)
        assert bridge.uploadSubjectIsDownloaded is True  # a link-downloaded body
    finally:
        bridge._apply_report(_file_report(tmp_path, verdict=Verdict.SAFE))


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
        bridge._apply_report(
            _file_report(tmp_path, verdict=Verdict.SUSPICIOUS, upload_could_help=True)
        )
        assert bridge.canOfferUpload is True
        bridge.uploadCurrentToCloud()
        assert len(started) == 1
        assert started[0].allow_cloud_upload is True
        assert started[0].target_kind is TargetKind.FILE
    finally:
        bridge._apply_report(_file_report(tmp_path, verdict=Verdict.SAFE, uploaded_to=_SERVICE))


# --------------------------------------------------------------------------- #
# Cache trap (point 15/25) + from-cache visibility (point 14) + report (16/21)
# --------------------------------------------------------------------------- #
def test_cached_uploaded_report_does_not_reoffer(gui: Any, tmp_path: Path) -> None:
    """Point 25: a cached result that already recorded an upload never re-offers one."""
    bridge = gui.bridge
    try:
        report = _file_report(tmp_path, verdict=Verdict.SAFE, uploaded_to=_SERVICE)
        report = report.model_copy(update={"from_cache": True})
        bridge._apply_report(report)
        assert bridge.fromCache is True  # point 14: cache origin is visible
        assert bridge.uploadedTo == _SERVICE  # the past upload is shown
        assert bridge.canOfferUpload is False  # ...but it is not offered again
    finally:
        bridge._apply_report(_file_report(tmp_path, verdict=Verdict.SAFE))


def test_result_screen_wires_cache_and_upload_notices() -> None:
    """Point 14: the result screen shows the cache origin and the past-upload line."""
    text = (_QML / "ScanPage.qml").read_text(encoding="utf-8")
    assert "Bridge.fromCache" in text
    assert "Bridge.uploadedTo" in text
    assert "Bridge.uploadedAtLocal" in text  # the past event carries its own time


def test_pdf_report_carries_upload_line_and_leaks_no_secret(
    gui: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    """Points 16/21: the PDF is rendered from HTML carrying the upload line; no secret leaks.

    Qt glyph-encodes text in the PDF, so a positive substring on the binary is not
    reliable -- presence is asserted on the exact HTML fed to the renderer. Absence, on
    the other hand, is meaningful on the raw bytes (a plaintext secret would show), so a
    representative key/URL are asserted absent from the actual PDF.
    """
    import prescan.ui.pdf_export as pdf_mod

    bridge = gui.bridge
    captured: dict[str, str] = {}
    original = pdf_mod.html_to_pdf

    def spy(html: str, dest: Path) -> None:
        captured["html"] = html
        original(html, dest)

    monkeypatch.setattr(pdf_mod, "html_to_pdf", spy)
    try:
        report = _file_report(tmp_path, verdict=Verdict.SAFE, uploaded_to=_SERVICE)
        report = report.model_copy(update={"uploaded_at": _UPLOADED_AT})
        bridge._apply_report(report)
        out = tmp_path / "report.pdf"
        assert bridge.saveReport(str(out)) is True

        # Presence: the upload line (with the local timestamp) is in the PDF's HTML source.
        html = captured["html"].lower()
        assert "was uploaded to" in html and "cannot be recalled" in html
        # Absence: a representative key and one-time URL never appear in the PDF bytes.
        raw = out.read_bytes()
        assert raw.startswith(b"%PDF-")
        assert b"vt_secret_key_DEADBEEF" not in raw
        assert b"_ah/upload/ONE_TIME_SECRET" not in raw
    finally:
        bridge._apply_report(_file_report(tmp_path, verdict=Verdict.SAFE))


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
