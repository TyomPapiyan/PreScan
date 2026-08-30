"""Tests for core/engines/static_pe.py: malformed PE must never crash (§10.4)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path

import pytest

from prescan.core.engines.base import ScanContext
from prescan.core.engines.static_pe import StaticPEEngine
from prescan.core.models import FileInfo, Severity
from tests.fixtures.broken_pe import garbage_headers, truncated_pe
from tests.fixtures.pe import minimal_pe


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
@pytest.mark.parametrize("factory", [truncated_pe, garbage_headers])
async def test_broken_pe_does_not_crash(tmp_path: Path, factory: Callable[[], bytes]) -> None:
    target = tmp_path / "bad.exe"
    target.write_bytes(factory())
    signals = await StaticPEEngine().scan(_ctx(target, tmp_path))
    # Either no signals or a single INFO parse-failure note; never an exception.
    assert all(s.severity is Severity.INFO for s in signals) or signals == []


@pytest.mark.asyncio
async def test_non_pe_yields_no_signals(tmp_path: Path) -> None:
    target = tmp_path / "note.txt"
    target.write_bytes(b"just some text, not a binary")
    signals = await StaticPEEngine().scan(_ctx(target, tmp_path))
    assert signals == []


async def _keys(target: Path, tmp_path: Path) -> set[str]:
    signals = await StaticPEEngine().scan(_ctx(target, tmp_path))
    return {s.title_key for s in signals}


@pytest.mark.asyncio
async def test_high_entropy_section_flagged(tmp_path: Path) -> None:
    target = tmp_path / "packed.exe"
    target.write_bytes(minimal_pe(high_entropy=True))
    signals = await StaticPEEngine().scan(_ctx(target, tmp_path))
    entropy = next(s for s in signals if s.title_key == "signal.static.high_entropy")
    assert entropy.severity is Severity.MEDIUM
    assert entropy.data["packing_only"] is True
    assert entropy.data["escalates"] is True


@pytest.mark.asyncio
async def test_injection_imports_flagged(tmp_path: Path) -> None:
    target = tmp_path / "injector.exe"
    target.write_bytes(minimal_pe(imports=True))
    signals = await StaticPEEngine().scan(_ctx(target, tmp_path))
    inj = next(s for s in signals if s.title_key == "signal.static.injection_imports")
    assert inj.severity is Severity.HIGH
    assert "T1055" in inj.mitre


@pytest.mark.asyncio
async def test_large_overlay_flagged(tmp_path: Path) -> None:
    target = tmp_path / "overlay.exe"
    target.write_bytes(minimal_pe(overlay=2 * 1024 * 1024))
    assert "signal.static.large_overlay" in await _keys(target, tmp_path)


@pytest.mark.asyncio
async def test_clean_pe_has_no_escalating_signals(tmp_path: Path) -> None:
    target = tmp_path / "clean.exe"
    target.write_bytes(minimal_pe())
    signals = await StaticPEEngine().scan(_ctx(target, tmp_path))
    assert not any(s.data.get("escalates") for s in signals)
