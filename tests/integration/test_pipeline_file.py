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

# The clean reference binary for the false-positive guard (§8.6), per platform.
_CLEAN_BINARY = (
    Path(r"C:\Windows\System32\notepad.exe") if sys.platform == "win32" else Path("/bin/ls")
)


@pytest.mark.asyncio
async def test_clean_binary_is_never_flagged() -> None:
    """§8.6: a known-clean OS binary must never be SUSPICIOUS or DANGEROUS.

    Runs on both platforms with each platform's own reference binary — this is
    the primary false-positive guard and must not be silently skipped.
    """
    if not _CLEAN_BINARY.exists():
        pytest.skip(f"reference clean binary not present: {_CLEAN_BINARY}")
    request = ScanRequest(target_kind=TargetKind.FILE, file_path=_CLEAN_BINARY, allow_network=False)
    report = await Pipeline(AppConfig.load()).run(request)
    assert report.verdict in {Verdict.SAFE, Verdict.UNKNOWN}
    assert report.verdict not in {Verdict.SUSPICIOUS, Verdict.DANGEROUS}
    assert report.file is not None
    assert report.file.sha256


@pytest.mark.skipif(sys.platform == "win32", reason="asserts the Linux Defender skip")
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
async def test_second_scan_comes_from_cache(tmp_path: Path) -> None:
    from prescan.core.storage import Storage

    target = tmp_path / "blob.bin"
    target.write_bytes(b"cache me" * 100)
    storage = Storage(tmp_path / "db.sqlite")
    pipeline = Pipeline(AppConfig.load(), storage)
    request = ScanRequest(target_kind=TargetKind.FILE, file_path=target, allow_network=False)

    first = await pipeline.run(request)
    assert first.from_cache is False

    second = await pipeline.run(request)
    assert second.from_cache is True
    assert second.file is not None
    assert second.file.sha256 == first.file.sha256  # type: ignore[union-attr]


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
