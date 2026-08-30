"""Tests for core/hashing.py."""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

import pytest

from prescan.core.errors import ScanCancelled
from prescan.core.hashing import fuzzy_hash, hash_file


@pytest.mark.asyncio
async def test_hash_file_matches_hashlib(tmp_path: Path) -> None:
    data = b"prescan test payload" * 1000
    target = tmp_path / "blob.bin"
    target.write_bytes(data)

    digests = await hash_file(target)

    assert digests["md5"] == hashlib.md5(data).hexdigest()
    assert digests["sha1"] == hashlib.sha1(data).hexdigest()
    assert digests["sha256"] == hashlib.sha256(data).hexdigest()


@pytest.mark.asyncio
async def test_hash_file_honours_cancel(tmp_path: Path) -> None:
    target = tmp_path / "blob.bin"
    target.write_bytes(b"x" * (4 * 1024 * 1024))
    cancel = asyncio.Event()
    cancel.set()
    with pytest.raises(ScanCancelled):
        await hash_file(target, cancel=cancel)


def test_fuzzy_hash_returns_string(tmp_path: Path) -> None:
    target = tmp_path / "blob.bin"
    target.write_bytes(b"the quick brown fox " * 500)
    assert isinstance(fuzzy_hash(target), str)
