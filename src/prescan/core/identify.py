"""Real file type by content signature, and extension-mismatch detection.

Type is decided by content only (puremagic). The filename extension is used
solely to compute the mismatch flag: content that contradicts the claimed
extension (``invoice.pdf`` that is really a PE) or a deceptive double extension
(``invoice.pdf.exe``) is what makes malware masquerade as a document.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import structlog

log = structlog.get_logger(__name__)

_UNKNOWN_TYPE: Final = "unknown"
_UNKNOWN_MIME: Final = "application/octet-stream"

#: Final extensions that mean "this runs code when opened".
EXECUTABLE_EXTS: Final = frozenset(
    {
        ".exe",
        ".scr",
        ".com",
        ".msi",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js",
        ".jar",
        ".apk",
        ".dll",
        ".sh",
        ".run",
    }
)

#: "Safe looking" extensions commonly used as decoys in double extensions.
DECOY_EXTS: Final = frozenset(
    {
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".txt",
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".zip",
    }
)


def _candidate_extensions(path: Path) -> tuple[str, str, set[str]]:
    """Return (detected_type, detected_mime, plausible_extensions) via puremagic."""
    import puremagic

    try:
        matches = puremagic.magic_file(str(path))
    except (puremagic.PureError, OSError, ValueError) as exc:
        log.debug("identify.magic_failed", path=str(path), error=str(exc))
        return _UNKNOWN_TYPE, _UNKNOWN_MIME, set()

    if not matches:
        return _UNKNOWN_TYPE, _UNKNOWN_MIME, set()

    best = matches[0]
    detected_type = best.name or _UNKNOWN_TYPE
    detected_mime = best.mime_type or _UNKNOWN_MIME
    exts = {m.extension.lower() for m in matches if m.extension}
    return detected_type, detected_mime, exts


def _has_deceptive_double_extension(name: str) -> bool:
    """True for names like ``foo.pdf.exe``: decoy inner + executable final."""
    parts = name.lower().rsplit(".", 2)
    if len(parts) < 3:
        return False
    inner = f".{parts[-2]}"
    final = f".{parts[-1]}"
    return final in EXECUTABLE_EXTS and inner in DECOY_EXTS


def identify(path: Path) -> tuple[str, str, bool]:
    """Return (detected_type, detected_mime, extension_mismatch).

    Detection is by content signature only. The filename extension is used
    solely to compute the mismatch flag (invoice.pdf.exe).
    """
    detected_type, detected_mime, candidate_exts = _candidate_extensions(path)

    declared = path.suffix.lower()
    mismatch = False

    # Content type contradicts the claimed final extension.
    if declared and candidate_exts and declared not in candidate_exts:
        mismatch = True

    # Deceptive double extension regardless of content detection.
    if _has_deceptive_double_extension(path.name):
        mismatch = True

    return detected_type, detected_mime, mismatch
