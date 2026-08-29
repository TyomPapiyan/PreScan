"""Tests for core/archives.py: bomb, traversal and corruption guards."""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from prescan.core.archives import safe_extract
from prescan.core.errors import ArchiveBombError, ArchiveError, ArchiveTraversalError
from tests.fixtures.zipbomb import ratio_bomb


def test_extracts_normal_zip(tmp_path: Path) -> None:
    archive = tmp_path / "ok.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("a.txt", "hello")
        zf.writestr("dir/b.txt", "world")
    out = safe_extract(archive, tmp_path / "out")
    assert len(out) == 2
    assert (tmp_path / "out" / "a.txt").read_text() == "hello"


def test_zip_bomb_raises(tmp_path: Path) -> None:
    archive = tmp_path / "bomb.zip"
    archive.write_bytes(ratio_bomb(payload_size=50 * 1024 * 1024))
    with pytest.raises(ArchiveBombError):
        safe_extract(archive, tmp_path / "out")


def test_path_traversal_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "evil.zip"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        # Write an entry that escapes the destination directory.
        zf.writestr("../../evil.txt", "pwned")
    archive.write_bytes(buffer.getvalue())
    with pytest.raises(ArchiveTraversalError):
        safe_extract(archive, tmp_path / "out")


def test_truncated_zip_raises_archive_error(tmp_path: Path) -> None:
    archive = tmp_path / "broken.zip"
    full = io.BytesIO()
    with zipfile.ZipFile(full, "w") as zf:
        zf.writestr("a.txt", "hello world" * 100)
    archive.write_bytes(full.getvalue()[:40])  # cut it off
    with pytest.raises(ArchiveError):
        safe_extract(archive, tmp_path / "out")


def test_extracts_tar(tmp_path: Path) -> None:
    payload = tmp_path / "a.txt"
    payload.write_text("hello tar")
    archive = tmp_path / "ok.tar"
    with tarfile.open(archive, "w") as tf:
        tf.add(payload, arcname="a.txt")
    out = safe_extract(archive, tmp_path / "out")
    assert (tmp_path / "out" / "a.txt").read_text() == "hello tar"
    assert len(out) == 1


def test_nested_archive_is_recursed(tmp_path: Path) -> None:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("inner.txt", "deep")
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as zf:
        zf.writestr("inner.zip", inner.getvalue())
    out = safe_extract(outer, tmp_path / "out", max_depth=2)
    assert any(p.name == "inner.txt" for p in out)


def test_file_count_budget(tmp_path: Path) -> None:
    archive = tmp_path / "many.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for i in range(20):
            zf.writestr(f"f{i}.txt", "x")
    with pytest.raises(ArchiveBombError):
        safe_extract(archive, tmp_path / "out", max_files=5)
