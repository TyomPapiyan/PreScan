"""Tests for core/url/downloader.py: neutral name, perms, guaranteed cleanup."""

from __future__ import annotations

import asyncio
import stat
import sys
from pathlib import Path

import httpx
import pytest
import respx

from prescan.core.errors import DownloadError
from prescan.core.url.downloader import safe_download

_URL = "https://x.test/evil.exe"


@respx.mock
@pytest.mark.asyncio
async def test_download_uses_neutral_name_and_content(tmp_path: Path) -> None:
    respx.get(_URL).mock(return_value=httpx.Response(200, content=b"payload" * 100))
    path = await safe_download(
        _URL, tmp_path, max_bytes=1_000_000, timeout_s=30, cancel=asyncio.Event()
    )
    assert path.name == "download.bin"  # original .exe extension discarded
    assert path.read_bytes() == b"payload" * 100


@respx.mock
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file mode semantics")
@pytest.mark.asyncio
async def test_downloaded_file_is_0600_no_exec(tmp_path: Path) -> None:
    respx.get(_URL).mock(return_value=httpx.Response(200, content=b"data"))
    path = await safe_download(
        _URL, tmp_path, max_bytes=1_000_000, timeout_s=30, cancel=asyncio.Event()
    )
    mode = path.stat().st_mode
    assert stat.S_IMODE(mode) == 0o600
    assert not (mode & 0o111)  # no executable bit for anyone


@respx.mock
@pytest.mark.asyncio
async def test_oversize_download_raises_and_cleans_up(tmp_path: Path) -> None:
    respx.get(_URL).mock(return_value=httpx.Response(200, content=b"x" * 50_000))
    before = set(tmp_path.iterdir())
    with pytest.raises(DownloadError):
        await safe_download(_URL, tmp_path, max_bytes=1_000, timeout_s=30, cancel=asyncio.Event())
    # The temp working directory must be gone — nothing left behind (§7.2).
    assert set(tmp_path.iterdir()) == before


@respx.mock
@pytest.mark.asyncio
async def test_cancel_midway_cleans_up(tmp_path: Path) -> None:
    respx.get(_URL).mock(return_value=httpx.Response(200, content=b"x" * 200_000))
    cancel = asyncio.Event()
    cancel.set()  # cancelled before the first chunk is accepted
    before = set(tmp_path.iterdir())
    with pytest.raises(DownloadError):
        await safe_download(_URL, tmp_path, max_bytes=10_000_000, timeout_s=30, cancel=cancel)
    assert set(tmp_path.iterdir()) == before
