"""Tests for core/identify.py."""

from __future__ import annotations

from pathlib import Path

from prescan.core.identify import identify


def test_identify_elf_binary() -> None:
    detected_type, _mime, mismatch = identify(Path("/bin/ls"))
    assert "ELF" in detected_type
    assert mismatch is False  # no declared extension to contradict


def test_deceptive_double_extension_flagged(tmp_path: Path) -> None:
    target = tmp_path / "invoice.pdf.exe"
    target.write_bytes(b"MZ" + b"\x00" * 128)
    _type, _mime, mismatch = identify(target)
    assert mismatch is True


def test_content_contradicts_extension(tmp_path: Path) -> None:
    # A PDF-claimed file whose content is a PNG signature.
    target = tmp_path / "photo.pdf"
    target.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
    _type, _mime, mismatch = identify(target)
    assert mismatch is True


def test_matching_extension_not_flagged(tmp_path: Path) -> None:
    target = tmp_path / "photo.png"
    target.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
    _type, _mime, mismatch = identify(target)
    assert mismatch is False
