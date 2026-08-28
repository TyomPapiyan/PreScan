"""Malformed-PE generators for robustness tests (spec §13.2).

Used to prove that the static-analysis engine never crashes on hostile input
(§10.4). Fully fleshed out on M1 alongside ``tests/engines/test_static_pe.py``.
"""

from __future__ import annotations


def truncated_pe() -> bytes:
    """Return a PE that has a valid 'MZ' header but is cut off mid-structure."""
    # 'MZ' magic followed by a bogus e_lfanew pointing past the end of the data.
    return b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00"


def garbage_headers() -> bytes:
    """Return bytes that look like a PE but carry nonsensical header fields."""
    return b"MZ" + bytes(range(256)) * 2
