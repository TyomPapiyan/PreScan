"""Tests for core/models.py: request validation and report round-trip."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from prescan.core.models import (
    ScanReport,
    ScanRequest,
    Severity,
    Signal,
    SourceKind,
    TargetKind,
    Verdict,
)


def test_file_request_requires_path() -> None:
    with pytest.raises(ValidationError):
        ScanRequest(target_kind=TargetKind.FILE)


def test_url_request_requires_url() -> None:
    with pytest.raises(ValidationError):
        ScanRequest(target_kind=TargetKind.URL)


def test_request_rejects_both_targets() -> None:
    with pytest.raises(ValidationError):
        ScanRequest(target_kind=TargetKind.FILE, file_path="/bin/ls", url="http://x")


def test_request_forbids_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        ScanRequest(target_kind=TargetKind.FILE, file_path="/bin/ls", bogus=1)


def test_signal_is_frozen() -> None:
    signal = Signal(
        source="clamav",
        kind=SourceKind.LOCAL_ENGINE,
        severity=Severity.CRITICAL,
        title_key="k",
        title_en="t",
    )
    with pytest.raises(ValidationError):
        signal.severity = Severity.LOW  # type: ignore[misc]


def _make_report() -> ScanReport:
    now = datetime.now(UTC)
    return ScanReport(
        scan_id="abc",
        app_version="0.0.0",
        request=ScanRequest(target_kind=TargetKind.FILE, file_path="/bin/ls"),
        started_at=now,
        finished_at=now,
        duration_s=0.0,
        verdict=Verdict.UNKNOWN,
        risk_score=0,
        verdict_reason_key="verdict.unknown",
        verdict_reason_en="reason",
    )


def test_report_round_trips_through_json() -> None:
    from prescan.core.report import from_json, to_json

    report = _make_report()
    restored = from_json(to_json(report))
    assert restored == report


def test_risk_score_bounds_enforced() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValidationError):
        ScanReport(
            scan_id="abc",
            app_version="0.0.0",
            request=ScanRequest(target_kind=TargetKind.FILE, file_path="/bin/ls"),
            started_at=now,
            finished_at=now,
            duration_s=0.0,
            verdict=Verdict.UNKNOWN,
            risk_score=101,
            verdict_reason_key="k",
            verdict_reason_en="r",
        )
