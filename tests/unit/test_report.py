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
from prescan.core.report import to_html


def _report() -> ScanReport:
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
    )


def test_to_html_contains_verdict_and_escapes() -> None:
    html = to_html(_report())
    assert "SUSPICIOUS".lower() in html.lower()
    assert "x.exe" in html
    # Signal title is HTML-escaped, not injected raw.
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "not an antivirus" in html
