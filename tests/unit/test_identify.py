"""Tests for core/identify.py."""

from __future__ import annotations

from pathlib import Path

from prescan.core.identify import identify
from tests.fixtures.elf import minimal_elf


def test_identify_elf_binary(tmp_path: Path) -> None:
    target = tmp_path / "sample"  # no extension -> nothing to contradict
    target.write_bytes(minimal_elf())
    detected_type, _mime, mismatch = identify(target)
    assert "ELF" in detected_type
    assert mismatch is False


def test_deceptive_double_extension_flagged(tmp_path: Path) -> None:
    target = tmp_path / "invoice.pdf.exe"
    target.write_bytes(b"MZ" + b"\x00" * 128)
    _type, _mime, mismatch = identify(target)
    assert mismatch is True


def test_executable_content_under_safe_extension_flagged(tmp_path: Path) -> None:
    # A PDF-claimed file whose content is actually a PE/DOS executable.
    target = tmp_path / "invoice.pdf"
    target.write_bytes(b"MZ\x90\x00" + b"\x00" * 128)
    _type, _mime, mismatch = identify(target)
    assert mismatch is True


def test_benign_extension_mismatch_not_flagged(tmp_path: Path) -> None:
    # A text file with an odd extension is NOT a security mismatch (§8.6).
    target = tmp_path / "notes.abc123"
    target.write_bytes(b"just some plain text, nothing dangerous here\n")
    _type, _mime, mismatch = identify(target)
    assert mismatch is False


def test_matching_extension_not_flagged(tmp_path: Path) -> None:
    target = tmp_path / "photo.png"
    target.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
    _type, _mime, mismatch = identify(target)
    assert mismatch is False
