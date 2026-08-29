"""Minimal valid ELF header generator for cross-platform tests.

Lets the identify/signature tests run on any OS without depending on a system
binary like ``/bin/ls`` that is absent on Windows.
"""

from __future__ import annotations

import struct


def minimal_elf() -> bytes:
    """Return a 64-byte ELF64 header detected as an ELF executable.

    Enough for content-based type detection (puremagic) and LIEF parsing; it has
    no section or program headers, which is fine for these tests.
    """
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8  # ELF64, little-endian, SysV
    header = e_ident + struct.pack("<HHI", 2, 0x3E, 1)  # ET_EXEC, EM_X86_64, version 1
    return header + b"\x00" * (64 - len(header))
