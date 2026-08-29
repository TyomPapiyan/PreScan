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
