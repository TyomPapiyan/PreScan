"""Tests for core/identify.py, including the §5.4 extension_mismatch table."""

from __future__ import annotations

import io
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest

from prescan.core.identify import identify
from tests.fixtures.elf import minimal_elf
from tests.fixtures.pe import minimal_pe

_PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
_TEXT = b"just some plain text, nothing dangerous here\n"


def _zip_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("a.txt", "hello")
    return buffer.getvalue()


# The nine rows of the §5.4 extension_mismatch contract table.
# (filename, content factory, expected extension_mismatch)
_CASES: list[tuple[str, Callable[[], bytes], bool]] = [
    ("invoice.pdf", minimal_pe, True),  # A: executable content under .pdf
    ("photo.png.exe", minimal_pe, True),  # A and B
    ("report.pdf.exe", lambda: _TEXT, True),  # B: decoy .pdf + exec .exe
    ("setup.exe", minimal_pe, False),  # declared extension is itself executable
    ("ls", minimal_elf, False),  # no declared extension
    ("photo.pdf", lambda: _PNG, False),  # content not executable
    ("notes.log", lambda: _TEXT, False),  # content not executable
    ("tmp.a1b2c3", lambda: _TEXT, False),  # odd suffix, benign content
    ("archive.zip", _zip_bytes, False),  # content not executable
]


@pytest.mark.parametrize(("name", "content", "expected"), _CASES, ids=[row[0] for row in _CASES])
def test_extension_mismatch_contract(
    tmp_path: Path, name: str, content: Callable[[], bytes], expected: bool
) -> None:
    target = tmp_path / name
    target.write_bytes(content())
    _type, _mime, mismatch = identify(target)
    assert mismatch is expected


def test_identify_elf_binary(tmp_path: Path) -> None:
    target = tmp_path / "sample"
    target.write_bytes(minimal_elf())
    detected_type, _mime, mismatch = identify(target)
    assert "ELF" in detected_type
    assert mismatch is False
