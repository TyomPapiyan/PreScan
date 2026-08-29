"""Tests for core/engines/documents.py: PDF and archive routing."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from prescan.core.engines.base import ScanContext
from prescan.core.engines.documents import DocumentsEngine
from prescan.core.models import FileInfo
from tests.fixtures.zipbomb import ratio_bomb


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
async def test_pdf_openaction_flagged(tmp_path: Path) -> None:
    import pikepdf

    pdf = pikepdf.new()
    pdf.add_blank_page()
    pdf.Root.OpenAction = pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS="app.alert(1);")
    target = tmp_path / "doc.pdf"
    pdf.save(target)

    signals = await DocumentsEngine().scan(_ctx(target, tmp_path / "work"))
    keys = {s.title_key for s in signals}
    assert "signal.pdf.openaction" in keys


@pytest.mark.asyncio
async def test_archive_bomb_flagged(tmp_path: Path) -> None:
    target = tmp_path / "bomb.zip"
    target.write_bytes(ratio_bomb(payload_size=50 * 1024 * 1024))
    signals = await DocumentsEngine().scan(_ctx(target, tmp_path / "work"))
    assert any(s.title_key == "signal.archive.bomb" for s in signals)


@pytest.mark.asyncio
async def test_plain_text_yields_nothing(tmp_path: Path) -> None:
    target = tmp_path / "note.txt"
    target.write_bytes(b"just plain text")
    signals = await DocumentsEngine().scan(_ctx(target, tmp_path / "work"))
    assert signals == []
