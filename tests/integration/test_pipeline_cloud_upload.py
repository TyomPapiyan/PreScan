"""Stage 13 in the file pipeline: consent gating, no-point gates, scoring, and the
default-config safety fuse. No real network -- fakes for the controlled cases, respx
for the fuse -- and no test touches the clock.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

import prescan.core.config as config_mod
import prescan.core.pipeline as pipeline_mod
from prescan.core.config import AppConfig
from prescan.core.models import (
    Availability,
    ScanRequest,
    Severity,
    Signal,
    SourceKind,
    TargetKind,
    UploadOutcome,
    Verdict,
)
from prescan.core.pipeline import Pipeline

_SENT_AT = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)


def _vt_signal(**data: Any) -> Signal:
    return Signal(
        source="virustotal",
        kind=SourceKind.CLOUD_SCAN,
        severity=Severity.INFO,
        title_key="k",
        title_en="vt",
        data=data,
    )


def _ml(prob: float) -> Signal:
    return Signal(
        source="ml",
        kind=SourceKind.ML,
        severity=Severity.INFO,
        title_key="k",
        title_en="ml",
        data={"probability": prob},
    )


class _FakeHash:
    name = "virustotal"
    kind = SourceKind.CLOUD_REPUTATION
    stage_id = "reputation"
    requires_key = True

    def __init__(
        self,
        signals: list[Signal],
        *,
        availability: Availability = Availability.READY,
        raises: bool = False,
    ) -> None:
        self._signals = signals
        self._availability = availability
        self._raises = raises

    async def availability(self) -> tuple[Availability, str]:
        return self._availability, "ready"

    async def lookup_hash(self, sha256: str) -> list[Signal]:
        if self._raises:
            raise RuntimeError("reputation lookup failed")
        return list(self._signals)


class _FakeUpload:
    name = "virustotal"
    supports_upload = True
    max_upload_bytes = 1_000_000

    def __init__(
        self,
        *,
        availability: Availability = Availability.READY,
        outcome: UploadOutcome | None = None,
    ) -> None:
        self._availability = availability
        self._outcome = outcome or UploadOutcome(availability=Availability.READY)
        self.upload_calls = 0

    async def availability(self) -> tuple[Availability, str]:
        return self._availability, "detail"

    async def upload_file(self, path: Path, *, cancel: object = None) -> UploadOutcome:
        self.upload_calls += 1
        return self._outcome


async def _run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    never_upload: bool,
    allow_upload: bool,
    hash_signals: list[Signal] | None = None,
    hash_availability: Availability = Availability.READY,
    hash_raises: bool = False,
    engine_signals: list[Signal] | None = None,
    upload: _FakeUpload | None = None,
) -> Any:
    file = tmp_path / "f.bin"
    file.write_bytes(b"data")

    async def _no_engines(self: Pipeline, *a: object, **k: object) -> tuple[list[Signal], bool]:
        return list(engine_signals or []), False

    hash_provider = _FakeHash(
        hash_signals or [], availability=hash_availability, raises=hash_raises
    )
    monkeypatch.setattr(Pipeline, "_run_engines", _no_engines)
    monkeypatch.setattr(pipeline_mod, "build_hash_providers", lambda *a, **k: [hash_provider])
    monkeypatch.setattr(
        pipeline_mod, "build_upload_provider", lambda *a, **k: upload or _FakeUpload()
    )

    config = AppConfig.load()
    config.never_upload_files = never_upload
    request = ScanRequest(
        target_kind=TargetKind.FILE,
        file_path=file,
        allow_network=True,
        allow_cloud_upload=allow_upload,
    )
    return await Pipeline(config).run(request)


# --- consent gating: opting out is NOT unavailability (§6.2) ---------------- #
@pytest.mark.asyncio
async def test_lock_closed_no_upload_no_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    up = _FakeUpload()
    report = await _run(monkeypatch, tmp_path, never_upload=True, allow_upload=True, upload=up)
    assert up.upload_calls == 0
    assert report.incomplete is False and "cloud_upload" not in report.unavailable_sources


@pytest.mark.asyncio
async def test_lock_open_but_no_consent_no_upload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    up = _FakeUpload()
    report = await _run(monkeypatch, tmp_path, never_upload=False, allow_upload=False, upload=up)
    assert up.upload_calls == 0 and report.incomplete is False


# --- consent + gates: the upload runs and scores -------------------------- #
@pytest.mark.asyncio
async def test_upload_dangerous_records_upload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    decisive = _vt_signal(malicious=50)
    decisive = decisive.model_copy(
        update={"severity": Severity.CRITICAL, "decisive": True, "weight": 90}
    )
    up = _FakeUpload(
        outcome=UploadOutcome(
            sent=True, sent_at=_SENT_AT, signals=[decisive], availability=Availability.READY
        )
    )
    report = await _run(monkeypatch, tmp_path, never_upload=False, allow_upload=True, upload=up)
    assert up.upload_calls == 1
    assert report.verdict is Verdict.DANGEROUS
    assert report.uploaded_to == "virustotal" and report.uploaded_at == _SENT_AT


@pytest.mark.asyncio
async def test_upload_clean_can_reach_safe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    clean = _vt_signal(malicious=0, total=70, authoritative_clean=True)
    up = _FakeUpload(
        outcome=UploadOutcome(
            sent=True, sent_at=_SENT_AT, signals=[clean], availability=Availability.READY
        )
    )
    report = await _run(
        monkeypatch,
        tmp_path,
        never_upload=False,
        allow_upload=True,
        engine_signals=[_ml(0.1)],
        upload=up,
    )
    assert report.verdict is Verdict.SAFE  # cloud-clean is authoritative on par with hash (§8.3)
    assert report.uploaded_to == "virustotal"


# --- no-point gates: explained by INFO, NOT incomplete (point 11) ---------- #
@pytest.mark.asyncio
async def test_cloud_already_knows_hash_skips_upload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    known = _vt_signal(malicious=0, total=70, authoritative_clean=True)
    up = _FakeUpload()
    report = await _run(
        monkeypatch,
        tmp_path,
        never_upload=False,
        allow_upload=True,
        hash_signals=[known],
        upload=up,
    )
    assert up.upload_calls == 0 and report.incomplete is False
    skip = next(s for s in report.signals if s.source == "cloud_upload")
    assert "already knows" in skip.title_en
    # point 7: the skip INFO carries zero weight and is not decisive -- it never
    # moves the verdict, it only explains why the upload did not happen.
    assert skip.severity is Severity.INFO and skip.weight == 0 and skip.decisive is False


@pytest.mark.asyncio
async def test_already_dangerous_locally_skips_upload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hard = Signal(
        source="yara-x",
        kind=SourceKind.LOCAL_ENGINE,
        severity=Severity.CRITICAL,
        title_key="k",
        title_en="rule",
        decisive=True,
        weight=90,
    )
    up = _FakeUpload()
    report = await _run(
        monkeypatch,
        tmp_path,
        never_upload=False,
        allow_upload=True,
        engine_signals=[hard],
        upload=up,
    )
    assert up.upload_calls == 0 and report.incomplete is False
    assert report.verdict is Verdict.DANGEROUS
    assert any(s.source == "cloud_upload" and "dangerous" in s.title_en for s in report.signals)


# --- precondition: upload only when reputation established the file is unknown
# (points 5-6). If the upload provider's reputation stage did not run
# successfully, we have NOT established that the cloud lacks this file, so we do
# not send it -- privacy over completeness. An INFO explains it; not incomplete. #
@pytest.mark.asyncio
async def test_reputation_error_blocks_upload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    up = _FakeUpload()
    report = await _run(
        monkeypatch,
        tmp_path,
        never_upload=False,
        allow_upload=True,
        hash_raises=True,  # reputation stage fails
        upload=up,
    )
    assert up.upload_calls == 0
    skip = next(s for s in report.signals if s.source == "cloud_upload")
    assert "could not verify" in skip.title_en
    assert skip.severity is Severity.INFO and skip.weight == 0 and skip.decisive is False


@pytest.mark.asyncio
async def test_reputation_skipped_no_key_blocks_upload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    up = _FakeUpload()
    report = await _run(
        monkeypatch,
        tmp_path,
        never_upload=False,
        allow_upload=True,
        hash_availability=Availability.NO_KEY,  # reputation stage skipped
        upload=up,
    )
    assert up.upload_calls == 0
    skip = next(s for s in report.signals if s.source == "cloud_upload")
    assert "could not verify" in skip.title_en
    assert skip.severity is Severity.INFO and skip.weight == 0 and skip.decisive is False


# --- consented but cannot run: unavailable + incomplete (§6.1) ------------- #
@pytest.mark.asyncio
async def test_file_too_large_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    up = _FakeUpload()
    up.max_upload_bytes = 1  # 4-byte file exceeds it
    report = await _run(monkeypatch, tmp_path, never_upload=False, allow_upload=True, upload=up)
    assert up.upload_calls == 0
    assert "cloud_upload" in report.unavailable_sources and report.incomplete is True


@pytest.mark.asyncio
async def test_no_key_is_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    up = _FakeUpload(availability=Availability.NO_KEY)
    report = await _run(monkeypatch, tmp_path, never_upload=False, allow_upload=True, upload=up)
    assert up.upload_calls == 0
    assert "cloud_upload" in report.unavailable_sources and report.incomplete is True


@pytest.mark.asyncio
async def test_upload_timeout_records_upload_but_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outcome = UploadOutcome(
        sent=True,
        sent_at=_SENT_AT,
        availability=Availability.ERROR,
        detail="result not received in 180 s",
    )
    up = _FakeUpload(outcome=outcome)
    report = await _run(monkeypatch, tmp_path, never_upload=False, allow_upload=True, upload=up)
    assert up.upload_calls == 1
    assert "cloud_upload" in report.unavailable_sources and report.incomplete is True
    # The bytes left, so the fact is recorded even though no verdict came back (point 8).
    assert report.uploaded_to == "virustotal" and report.uploaded_at == _SENT_AT


# --- the safety fuse: default config never sends a file body (point 25) ---- #
@respx.mock
@pytest.mark.asyncio
async def test_default_config_sends_no_file_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No keys -> every network provider is skipped, nothing is sent. The upload POST
    # route must never be hit under the default (locked) config.
    monkeypatch.setattr(config_mod, "get_api_key", lambda _pid: None)
    upload_route = respx.post("https://www.virustotal.com/api/v3/files").mock(
        return_value=httpx.Response(200, json={"data": {"id": "X"}})
    )

    async def _no_engines(self: Pipeline, *a: object, **k: object) -> tuple[list[Signal], bool]:
        return [], False

    monkeypatch.setattr(Pipeline, "_run_engines", _no_engines)
    file = tmp_path / "f.bin"
    file.write_bytes(b"data")
    request = ScanRequest(
        target_kind=TargetKind.FILE, file_path=file, allow_network=True
    )  # defaults

    await Pipeline(AppConfig()).run(request)  # AppConfig() -> defaults: never_upload_files=True
    assert upload_route.called is False, "a file body was sent under the default config"
