"""Safe download into an isolated temp directory (§7.2).

The body is written to a neutral ``download.bin`` (original extension discarded),
mode ``0o600`` with the executable bit stripped, inside a fresh ``0o700`` temp
dir. A hard size cap aborts oversized downloads. On any failure the temp dir is
removed so nothing is left behind; the file is never opened or executed (§1.2).
"""

from __future__ import annotations

import asyncio
import contextlib
import shutil
import stat
import tempfile
from pathlib import Path

import httpx
import structlog

from prescan.core.errors import DownloadError

log = structlog.get_logger(__name__)

_CONNECT_TIMEOUT = 15.0
_NEUTRAL_NAME = "download.bin"


async def safe_download(
    url: str,
    dest_dir: Path,
    *,
    max_bytes: int,
    timeout_s: float,
    cancel: asyncio.Event,
) -> Path:
    """Download to a neutral filename (no executable extension), mode 0o600, no +x."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    workdir = Path(tempfile.mkdtemp(prefix="prescan-dl-", dir=dest_dir))
    _chmod(workdir, 0o700)
    target = workdir / _NEUTRAL_NAME

    try:
        await _stream_to_file(url, target, max_bytes=max_bytes, timeout_s=timeout_s, cancel=cancel)
        _harden(target)
        return target
    except BaseException:
        # Guaranteed cleanup on any failure, including cancellation (§7.2).
        shutil.rmtree(workdir, ignore_errors=True)
        raise


async def _stream_to_file(
    url: str,
    target: Path,
    *,
    max_bytes: int,
    timeout_s: float,
    cancel: asyncio.Event,
) -> None:
    """Stream the response body to disk, enforcing the size cap and cancellation."""
    timeout = httpx.Timeout(timeout_s, connect=_CONNECT_TIMEOUT)
    written = 0
    async with (
        httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client,
        client.stream("GET", url) as response,
    ):
        response.raise_for_status()
        with target.open("wb") as fh:
            async for chunk in response.aiter_bytes(chunk_size=64 * 1024):
                if cancel.is_set():
                    raise DownloadError("download cancelled")
                written += len(chunk)
                if written > max_bytes:
                    raise DownloadError(f"download exceeded {max_bytes} bytes")
                fh.write(chunk)


def _harden(path: Path) -> None:
    """Set mode 0o600 and strip any executable bits."""
    _chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600, no execute for anyone


def _chmod(path: Path, mode: int) -> None:
    """chmod that is a no-op where unsupported (e.g. Windows)."""
    with contextlib.suppress(OSError):  # pragma: no cover - platform dependent
        path.chmod(mode)
