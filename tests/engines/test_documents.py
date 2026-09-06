"""Tests for core/engines/documents.py: PDF and archive routing."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from prescan.core.engines.base import ScanContext
from prescan.core.engines.documents import DocumentsEngine
from prescan.core.models import FileInfo, Severity, Verdict
from prescan.core.scoring import score
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
async def test_pdf_openaction_with_javascript_escalates(tmp_path: Path) -> None:
    """Point 20: an automatic action that runs JavaScript is the dangerous combination --
    detection must NOT be lost: it escalates to SUSPICIOUS or worse.

    (Reworked from the old test that asserted /OpenAction alone was flagged: §I demotes a
    bare automatic action to informational, so the meaningful case is the active content.)
    """
    import pikepdf

    pdf = pikepdf.new()
    pdf.add_blank_page()
    pdf.Root.OpenAction = pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS="app.alert(1);")
    target = tmp_path / "doc.pdf"
    pdf.save(target)

    signals = await DocumentsEngine().scan(_ctx(target, tmp_path / "work"))
    assert any(s.title_key == "signal.pdf.javascript" and s.data.get("escalates") for s in signals)
    verdict, _r, _k, _rr = score(signals, had_authoritative_source=True)
    assert verdict in (Verdict.SUSPICIOUS, Verdict.DANGEROUS)


@pytest.mark.asyncio
async def test_pdf_openaction_alone_is_informational(tmp_path: Path) -> None:
    """Point 19: an automatic action with no active content (a plain GoTo) is INFO with
    zero weight and does not move the verdict -- clean PDFs commonly set it (§I)."""
    import pikepdf

    pdf = pikepdf.new()
    page = pdf.add_blank_page()
    # A benign navigation action: open at the first page. No JavaScript, no Launch, etc.
    pdf.Root.OpenAction = pikepdf.Dictionary(S=pikepdf.Name.GoTo, D=[page.obj, pikepdf.Name.Fit])
    target = tmp_path / "doc.pdf"
    pdf.save(target)

    signals = await DocumentsEngine().scan(_ctx(target, tmp_path / "work"))
    openaction = next(s for s in signals if s.title_key == "signal.pdf.openaction")
    assert openaction.severity is Severity.INFO
    assert openaction.weight == 0
    assert openaction.data.get("escalates") is not True
    # No escalating signal at all -> the verdict is not moved by the automatic action.
    assert not any(s.data.get("escalates") for s in signals)
    verdict, _r, _k, _rr = score(signals, had_authoritative_source=True)
    assert verdict not in (Verdict.SUSPICIOUS, Verdict.DANGEROUS)


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


def _minimal_docx(path: Path) -> None:
    """Write a minimal, valid macro-free OOXML .docx (a zip of the three core parts)."""
    import zipfile

    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.'
        'relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" ContentType="application/vnd.'
        'openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
        'relationships/officeDocument" Target="word/document.xml"/></Relationships>'
    )
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        "<w:body><w:p><w:r><w:t>hello</w:t></w:r></w:p></w:body></w:document>"
    )
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", rels)
        z.writestr("word/document.xml", document)


@pytest.mark.asyncio
async def test_macro_free_office_document_is_not_suspicious(tmp_path: Path) -> None:
    """A plain OOXML document with no macros must produce no escalating signal (point 6).

    Closes the office side of the clean-corpus guard, which had no Office samples on the
    build machine to measure. A document without macros must never be SUSPICIOUS.
    """
    target = tmp_path / "clean.docx"
    _minimal_docx(target)

    signals = await DocumentsEngine().scan(_ctx(target, tmp_path / "work"))

    assert not any(s.data.get("escalates") for s in signals), (
        f"a macro-free document escalated: {[s.title_en for s in signals]}"
    )
    verdict, _r, _k, _rr = score(signals, had_authoritative_source=True)
    assert verdict not in (Verdict.SUSPICIOUS, Verdict.DANGEROUS)
