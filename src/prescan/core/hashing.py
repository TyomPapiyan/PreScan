"""File hashing: md5/sha1/sha256 (streaming), imphash and fuzzy (ssdeep/CTPH).

Cryptographic hashes are computed in a single streaming pass to keep large
files cheap and the UI responsive (§9.9): the blocking read loop runs in a
worker thread and honours the cancel event between chunks.
"""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from prescan.core.errors import ScanCancelled

if TYPE_CHECKING:
    import lief

log = structlog.get_logger(__name__)

CHUNK_SIZE = 1024 * 1024  # 1 MiB, per §5.4


def _hash_sync(path: Path, cancel: asyncio.Event | None) -> dict[str, str]:
    """Compute md5/sha1/sha256 in one pass. Runs in a worker thread."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            if cancel is not None and cancel.is_set():
                raise ScanCancelled
            chunk = fh.read(CHUNK_SIZE)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


async def hash_file(path: Path, *, cancel: asyncio.Event | None = None) -> dict[str, str]:
    """Return md5/sha1/sha256 in a single streaming pass, chunk size 1 MiB."""
    return await asyncio.to_thread(_hash_sync, path, cancel)


def imphash(binary: lief.Binary) -> str | None:
    """Return the PE import hash, or None for non-PE or on failure."""
    try:
        import lief

        if not isinstance(binary, lief.PE.Binary):
            return None
        value = lief.PE.get_imphash(binary)
        return value or None
    except Exception as exc:  # noqa: BLE001 - untrusted binary, never crash (§10.4)
        log.debug("imphash.failed", error=str(exc))
        return None


def fuzzy_hash(path: Path) -> str | None:
    """Return the ssdeep/CTPH fuzzy hash via ppdeep, or None on failure."""
    try:
        import ppdeep

        value: str = ppdeep.hash_from_file(str(path))
        return value or None
    except Exception as exc:  # noqa: BLE001 - never crash on odd input (§10.4)
        log.debug("fuzzy_hash.failed", error=str(exc))
        return None
