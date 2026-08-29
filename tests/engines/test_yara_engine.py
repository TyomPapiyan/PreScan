"""Tests for core/engines/yara_engine.py using a small local rule."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from prescan.core.engines.base import ScanContext
from prescan.core.engines.yara_engine import YaraEngine
from prescan.core.models import FileInfo, Severity

_RULE = """
rule PRESCAN_TEST_HIGH {
    meta:
        severity = "high"
    strings:
        $a = "PRESCAN_MARKER_9Z"
    condition:
        $a
}
"""


def _ctx(path: Path, workdir: Path) -> ScanContext:
    info = FileInfo(
        path=path,
        name=path.name,
        size=path.stat().st_size,
        declared_extension=path.suffix,
        detected_type="data",
        detected_mime="application/octet-stream",
        md5="0" * 32,
        sha1="0" * 40,
        sha256="0" * 64,
    )
    return ScanContext(path=path, info=info, cancel=asyncio.Event(), timeout_s=30, workdir=workdir)


@pytest.mark.asyncio
async def test_no_rules_reports_no_rules(tmp_path: Path) -> None:
    engine = YaraEngine(tmp_path / "empty")
    availability, _detail = await engine.availability()
    assert availability.value == "no_rules"


@pytest.mark.asyncio
async def test_matching_rule_produces_decisive_high_signal(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "test.yar").write_text(_RULE)

    target = tmp_path / "sample.bin"
    target.write_bytes(b"........PRESCAN_MARKER_9Z........")

    engine = YaraEngine(rules_dir)
    availability, _ = await engine.availability()
    assert availability.value == "ready"

    signals = await engine.scan(_ctx(target, tmp_path))
    assert len(signals) == 1
    assert signals[0].severity is Severity.HIGH
    assert signals[0].decisive is True
    assert "PRESCAN_TEST_HIGH" in signals[0].detail


@pytest.mark.asyncio
async def test_non_matching_file_yields_no_signal(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "test.yar").write_text(_RULE)
    target = tmp_path / "clean.bin"
    target.write_bytes(b"nothing to see here")
    signals = await YaraEngine(rules_dir).scan(_ctx(target, tmp_path))
    assert signals == []
