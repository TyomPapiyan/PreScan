"""Minimal valid PE64 generator for static-analysis tests.

Builds a parseable PE with controllable properties so the LIEF static engine can
be exercised without shipping a real binary: a high-entropy section (packing),
the process-injection import triple, and a large overlay (§8.2/§8.4). LIEF in
this build cannot construct a PE from scratch, so we assemble the bytes by hand.
"""

from __future__ import annotations

import os
import struct

_FILE_ALIGN = 0x200
_SECT_ALIGN = 0x1000
_IMAGE_BASE = 0x140000000
_INJECTION = (b"VirtualAlloc", b"WriteProcessMemory", b"CreateRemoteThread")


def _align(n: int, a: int) -> int:
    return (n + a - 1) // a * a


def _build_idata(idata_rva: int) -> tuple[bytes, int, int]:
    """Return (idata bytes, import-directory RVA, import-directory size)."""
    idt = 0
    idt_size = 20 * 2  # one descriptor + null terminator
    ilt = idt + idt_size
    ilt_size = 8 * (len(_INJECTION) + 1)
    iat = ilt + ilt_size
    iat_size = 8 * (len(_INJECTION) + 1)
    names_off = iat + iat_size

    name_rvas: list[int] = []
    blob = b""
    cur = names_off
    for fn in _INJECTION:
        name_rvas.append(idata_rva + cur)
        entry = struct.pack("<H", 0) + fn + b"\x00"
        if len(entry) % 2:
            entry += b"\x00"
        blob += entry
        cur += len(entry)
    dll_rva = idata_rva + cur
    blob += b"kernel32.dll\x00"

    idt_bytes = struct.pack("<IIIII", idata_rva + ilt, 0, 0, dll_rva, idata_rva + iat)
    idt_bytes += struct.pack("<IIIII", 0, 0, 0, 0, 0)
    ilt_bytes = b"".join(struct.pack("<Q", r) for r in name_rvas) + struct.pack("<Q", 0)
    idata = idt_bytes + ilt_bytes + ilt_bytes + blob  # ILT reused as IAT
    return idata, idata_rva + idt, idt_size


def minimal_pe(*, high_entropy: bool = False, overlay: int = 0, imports: bool = False) -> bytes:
    """Assemble a minimal PE64 with the requested characteristics."""
    text = os.urandom(0x200) if high_entropy else b"\x90" * 0x200
    text_raw = _align(len(text), _FILE_ALIGN)
    text = text.ljust(text_raw, b"\x00")

    idata_rva = 0x2000
    idata = b""
    import_rva = import_size = 0
    if imports:
        idata, import_rva, import_size = _build_idata(idata_rva)
    idata_raw = _align(len(idata), _FILE_ALIGN) if idata else 0
    idata = idata.ljust(idata_raw, b"\x00")

    num_sections = 2 if imports else 1
    opt_header_size = 0xF0

    coff = struct.pack("<HHIIIHH", 0x8664, num_sections, 0, 0, 0, opt_header_size, 0x0022)

    size_of_image = (
        _align(idata_rva + max(idata_raw, _SECT_ALIGN), _SECT_ALIGN) if imports else 0x2000
    )

    opt = struct.pack("<HBBIIIII", 0x020B, 14, 0, text_raw, idata_raw, 0, 0x1000, 0x1000)
    opt += struct.pack("<Q", _IMAGE_BASE)
    opt += struct.pack("<II", _SECT_ALIGN, _FILE_ALIGN)
    opt += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)
    opt += struct.pack("<I", 0)
    opt += struct.pack("<II", size_of_image, _FILE_ALIGN)
    opt += struct.pack("<I", 0)
    opt += struct.pack("<HH", 3, 0)
    opt += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)
    opt += struct.pack("<I", 0)
    opt += struct.pack("<I", 16)
    dirs = [(0, 0)] * 16
    if imports:
        dirs[1] = (import_rva, import_size)
    for rva, size in dirs:
        opt += struct.pack("<II", rva, size)

    def section(name: bytes, vsize: int, rva: int, raw: int, ptr: int, chars: int) -> bytes:
        return (
            name.ljust(8, b"\x00")
            + struct.pack("<IIII", vsize, rva, raw, ptr)
            + struct.pack("<IIHH", 0, 0, 0, 0)
            + struct.pack("<I", chars)
        )

    text_ptr = _FILE_ALIGN
    sections = section(b".text", len(text), 0x1000, text_raw, text_ptr, 0x60000020)
    if imports:
        sections += section(
            b".idata", len(idata), idata_rva, idata_raw, text_ptr + text_raw, 0xC0000040
        )

    dos = (b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x80)).ljust(0x80, b"\x00")
    headers = (dos + b"PE\x00\x00" + coff + opt + sections).ljust(_FILE_ALIGN, b"\x00")

    body = headers + text
    if imports:
        body += idata
    if overlay:
        body += os.urandom(overlay)
    return body
