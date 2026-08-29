"""End-to-end file pipeline tests.

Known-clean system binaries must never be flagged SUSPICIOUS or DANGEROUS
(false-positive guard, §8.6). A cancelled scan yields a partial UNKNOWN report.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from prescan.core.config import AppConfig
from prescan.core.models import ScanRequest, StageStatus, TargetKind, Verdict
from prescan.core.pipeline import Pipeline

_CLEAN_BINARY = Path("/bin/ls")


@pytest.mark.skipif(sys.platform.startswith("win"), reason="Linux clean-file test")
@pytest.mark.asyncio
async def test_clean_binary_is_never_flagged() -> None:
    if not _CLEAN_BINARY.exists():
        pytest.skip("/bin/ls not present")
    request = ScanRequest(target_kind=TargetKind.FILE, file_path=_CLEAN_BINARY, allow_network=False)
    report = await Pipeline(AppConfig.load()).run(request)
    assert report.verdict in {Verdict.SAFE, Verdict.UNKNOWN}
    assert report.file is not None
    assert report.file.sha256


@pytest.mark.skipif(sys.platform.startswith("win"), reason="Linux clean-file test")
@pytest.mark.asyncio
async def test_defender_skipped_on_linux() -> None:
    if not _CLEAN_BINARY.exists():
        pytest.skip("/bin/ls not present")
    request = ScanRequest(target_kind=TargetKind.FILE, file_path=_CLEAN_BINARY, allow_network=False)
    report = await Pipeline(AppConfig.load()).run(request)
    defender_stage = next(s for s in report.stages if s.stage_id == "defender")
    assert defender_stage.status is StageStatus.SKIPPED
    assert defender_stage.availability.value == "unsupported_os"
    assert "defender" in report.unavailable_sources
    assert report.incomplete is True


@pytest.mark.asyncio
async def test_cancelled_scan_is_unknown(tmp_path: Path) -> None:
    target = tmp_path / "blob.bin"
    target.write_bytes(b"x" * 4096)
    cancel = asyncio.Event()
    cancel.set()
    request = ScanRequest(target_kind=TargetKind.FILE, file_path=target, allow_network=False)
    report = await Pipeline(AppConfig.load()).run(request, cancel=cancel)
    assert report.verdict is Verdict.UNKNOWN
    assert report.incomplete is True
