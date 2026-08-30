"""Quarantine: move a flagged file into an AES-encrypted zip.

The file is stored inside a password-protected (``infected``) AES-256 zip so it
cannot be executed or picked up by other tools, and the on-disk archive is
private (mode 0o600) with no executable bit. Restore extracts the original bytes
to a chosen location, again without the executable bit (§5.4).
"""

from __future__ import annotations

import contextlib
import json
import stat
from dataclasses import dataclass
from pathlib import Path

import pyzipper
import structlog

from prescan.core.config import Paths
from prescan.core.errors import PreScanError
from prescan.core.models import ScanReport
from prescan.core.report import to_json

log = structlog.get_logger(__name__)

#: Standard AV convention: quarantined malware is zipped under this password.
QUARANTINE_PASSWORD = b"infected"
_META_NAME = "prescan-report.json"


class QuarantineError(PreScanError):
    """A quarantine or restore operation failed."""


@dataclass
class QuarantineEntry:
    """A row in the quarantine store."""

    entry_id: str
    original_name: str
    verdict: str
    archive: Path


def _quarantine_dir() -> Path:
    paths = Paths.resolve()
    paths.quarantine_dir.mkdir(parents=True, exist_ok=True)
    return paths.quarantine_dir


def _harden(path: Path) -> None:
    with contextlib.suppress(OSError):  # pragma: no cover - platform dependent
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0o600, no execute bit


def quarantine(path: Path, report: ScanReport) -> Path:
    """Move the file into an AES-encrypted zip (password 'infected'), strip +x."""
    src = path.resolve()
    if not src.is_file():
        raise QuarantineError(f"not a file: {src}")
    entry_id = report.file.sha256 if report.file else src.name
    archive = _quarantine_dir() / f"{entry_id}.zip"

    try:
        data = src.read_bytes()
        with pyzipper.AESZipFile(
            archive, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
        ) as zf:
            zf.setpassword(QUARANTINE_PASSWORD)
            zf.writestr(src.name, data)
            zf.writestr(_META_NAME, to_json(report))
    except (OSError, pyzipper.BadZipFile) as exc:
        raise QuarantineError(f"could not quarantine {src.name}: {exc}") from exc

    _harden(archive)
    # Move semantics: remove the original once it is safely archived.
    with contextlib.suppress(OSError):
        src.chmod(stat.S_IRUSR | stat.S_IWUSR)
    src.unlink(missing_ok=True)
    log.info("quarantine.stored", entry_id=entry_id, archive=str(archive))
    return archive


def restore(entry_id: str, dest: Path) -> Path:
    """Restore the original file from quarantine to dest (mode 0o600, no +x)."""
    archive = _quarantine_dir() / f"{entry_id}.zip"
    if not archive.is_file():
        raise QuarantineError(f"no quarantine entry: {entry_id}")
    try:
        with pyzipper.AESZipFile(archive) as zf:
            zf.setpassword(QUARANTINE_PASSWORD)
            names = [n for n in zf.namelist() if n != _META_NAME]
            if not names:
                raise QuarantineError(f"quarantine entry is empty: {entry_id}")
            original_name = names[0]
            data = zf.read(original_name)
    except (OSError, pyzipper.BadZipFile, RuntimeError) as exc:
        raise QuarantineError(f"could not restore {entry_id}: {exc}") from exc

    target = dest / original_name if dest.is_dir() else dest
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    _harden(target)
    return target


def list_entries() -> list[QuarantineEntry]:
    """List quarantine entries, reading each archive's stored report metadata."""
    entries: list[QuarantineEntry] = []
    for archive in sorted(_quarantine_dir().glob("*.zip")):
        entry_id = archive.stem
        original_name, verdict = _read_meta(archive)
        entries.append(QuarantineEntry(entry_id, original_name, verdict, archive))
    return entries


def purge(entry_id: str) -> None:
    """Permanently delete a quarantine entry."""
    (_quarantine_dir() / f"{entry_id}.zip").unlink(missing_ok=True)


def _read_meta(archive: Path) -> tuple[str, str]:
    """Return (original_name, verdict) from an archive, tolerating any error."""
    try:
        with pyzipper.AESZipFile(archive) as zf:
            zf.setpassword(QUARANTINE_PASSWORD)
            names = [n for n in zf.namelist() if n != _META_NAME]
            original_name = names[0] if names else "?"
            verdict = "?"
            if _META_NAME in zf.namelist():
                meta = json.loads(zf.read(_META_NAME))
                verdict = str(meta.get("verdict", "?"))
    except (OSError, pyzipper.BadZipFile, ValueError, RuntimeError):
        return "?", "?"
    return original_name, verdict
