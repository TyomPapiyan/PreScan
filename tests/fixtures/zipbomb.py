"""Zip-bomb generator for archive-guard tests (spec §13.2).

Produces a small archive with a very high uncompressed-to-compressed ratio so
that ``core/archives.safe_extract`` trips its ratio guard and raises
``ArchiveBombError`` without ever writing the payload to disk. Expanded on M1
alongside ``tests/unit/test_archives.py``.
"""

from __future__ import annotations

import io
import zipfile


def ratio_bomb(*, payload_size: int = 50 * 1024 * 1024) -> bytes:
    """Return a ZIP whose single entry expands to ``payload_size`` of zeros."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("bomb.bin", b"\x00" * payload_size)
    return buffer.getvalue()
