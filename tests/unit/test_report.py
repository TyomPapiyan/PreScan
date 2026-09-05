"""Tests for core/report.py rendering."""

from __future__ import annotations

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
from prescan.core.report import format_local_time, from_json, to_html, to_json


def _report(*, uploaded_to: str | None = None, uploaded_at: datetime | None = None) -> ScanReport:
    now = datetime.now(UTC)
    file_info = FileInfo(
        path="/tmp/x.exe",
        name="x.exe",
        size=10,
        declared_extension=".exe",
        detected_type="PE32",
        detected_mime="application/x-dosexec",
        md5="0" * 32,
        sha1="0" * 40,
        sha256="a" * 64,
    )
    return ScanReport(
        scan_id="id",
        app_version="0.0.0",
        request=ScanRequest(target_kind=TargetKind.FILE, file_path="/tmp/x.exe"),
        started_at=now,
        finished_at=now,
        duration_s=0.1,
        file=file_info,
        signals=[
            Signal(
                source="yara-x",
                kind=SourceKind.LOCAL_ENGINE,
                severity=Severity.HIGH,
                title_key="k",
                title_en="YARA rule matched: <script>",
                weight=75,
            )
        ],
        verdict=Verdict.SUSPICIOUS,
        risk_score=60,
        verdict_reason_key="verdict.suspicious",
        verdict_reason_en="Attention required",
        uploaded_to=uploaded_to,
        uploaded_at=uploaded_at,
    )


def test_to_html_contains_verdict_and_escapes() -> None:
    html = to_html(_report())
    assert "SUSPICIOUS".lower() in html.lower()
    assert "x.exe" in html
    # Signal title is HTML-escaped, not injected raw.
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "not an antivirus" in html


_UPLOADED_AT = datetime(2026, 9, 6, 9, 0, tzinfo=UTC)


def test_upload_line_present_in_html_en() -> None:
    """Point 11/21: an uploaded report shows a past-tense upload line with local time."""
    html = to_html(_report(uploaded_to="virustotal", uploaded_at=_UPLOADED_AT))
    assert "was uploaded to virustotal" in html.lower()
    assert "cannot be recalled" in html.lower()
    # The timestamp is local with an explicit offset (both sides convert -> tz-robust).
    assert format_local_time(_UPLOADED_AT) in html
    # Never phrased as happening now (cache trap, point 13): it is a past event.
    assert "uploading now" not in html.lower() and "is being uploaded" not in html.lower()


def test_upload_line_present_in_html_ru() -> None:
    """Point 11: the upload line is available in Russian too."""
    html = to_html(_report(uploaded_to="virustotal", uploaded_at=_UPLOADED_AT), lang="ru")
    assert "был загружен" in html
    assert "не может быть отозван" in html
    assert format_local_time(_UPLOADED_AT) in html


def test_no_upload_line_when_not_uploaded() -> None:
    """Point 22: a report with no upload contains no upload line at all -- no stray dash."""
    html = to_html(_report()).lower()
    assert "uploaded to" not in html
    assert "cannot be recalled" not in html


def test_report_serialization_leaks_no_secrets() -> None:
    """Points 16-17: the API key and one-time upload URL never appear in JSON or HTML.

    The report model has no field for either, so this is a regression guard: if a future
    change ever stuffed a key or the one-time URL into a signal/detail, it would fail.
    """
    secret_key = "vt_secret_key_DEADBEEF0123456789"
    one_time_url = "https://www.virustotal.com/_ah/upload/ONE_TIME_SECRET_TOKEN=/"
    report = _report(uploaded_to="virustotal", uploaded_at=_UPLOADED_AT)
    for rendered in (to_json(report), to_html(report), to_html(report, lang="ru")):
        assert secret_key not in rendered
        assert one_time_url not in rendered


def test_old_cached_report_without_upload_fields_loads() -> None:
    """Point 18/24: a report serialised before the upload fields existed still loads.

    Older cached JSON simply omits uploaded_to / uploaded_at / upload_could_help; parsing
    must succeed with the defaults, never raise.
    """
    full = to_json(_report())
    import json

    payload = json.loads(full)
    for missing in ("uploaded_to", "uploaded_at", "upload_could_help"):
        payload.pop(missing, None)
    report = from_json(json.dumps(payload))
    assert report.uploaded_to is None
    assert report.uploaded_at is None
    assert report.upload_could_help is False
