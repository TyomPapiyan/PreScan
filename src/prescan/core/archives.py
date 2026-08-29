"""Safe archive extraction with decompression-bomb and path-traversal guards.

Untrusted archives are hostile input: an entry may try to escape the target
directory (``../../evil``) or expand to gigabytes from a few kilobytes (a zip
bomb). Every output path is confined to ``dest`` with ``is_relative_to`` and a
byte/ratio/count/depth budget is enforced before and during extraction (§10.5).
"""

from __future__ import annotations

import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import structlog

from prescan.core.errors import ArchiveBombError, ArchiveError, ArchiveTraversalError

log = structlog.get_logger(__name__)

_CHUNK: Final = 1024 * 1024  # 1 MiB
#: Below this uncompressed size the ratio guard is not applied (avoids flagging
#: tiny, highly-compressible files as bombs).
_RATIO_FLOOR: Final = 1024 * 1024


@dataclass
class _Budget:
    """Shared, mutable extraction budget across nested archives."""

    total_bytes: int = 0
    files: int = 0
    max_total_bytes: int = 4 * 1024**3
    max_files: int = 10_000
    max_ratio: int = 200

    def add_bytes(self, n: int) -> None:
        self.total_bytes += n
        if self.total_bytes > self.max_total_bytes:
            raise ArchiveBombError(
                f"uncompressed size exceeded budget ({self.max_total_bytes} bytes)"
            )

    def add_file(self) -> None:
        self.files += 1
        if self.files > self.max_files:
            raise ArchiveBombError(f"file count exceeded budget ({self.max_files})")


def _safe_target(dest: Path, name: str) -> Path:
    """Resolve an entry name inside dest, rejecting path traversal."""
    target = (dest / name).resolve()
    if target != dest and not target.is_relative_to(dest):
        raise ArchiveTraversalError(f"entry escapes destination: {name!r}")
    return target


def is_archive(path: Path) -> bool:
    """Return True if the path looks like a supported archive by content."""
    try:
        if zipfile.is_zipfile(path) or tarfile.is_tarfile(path):
            return True
        import py7zr

        return bool(py7zr.is_7zfile(path))
    except (OSError, ImportError):
        return False


def _extract_zip(archive: Path, dest: Path, budget: _Budget, results: list[Path]) -> None:
    """Extract a ZIP with declared-size pre-check and a hard cap while reading."""
    try:
        zf = zipfile.ZipFile(archive)
    except zipfile.BadZipFile as exc:
        raise ArchiveError(f"corrupt zip: {exc}") from exc
    with zf:
        infos = zf.infolist()
        if len(infos) > budget.max_files:
            raise ArchiveBombError(f"file count exceeded budget ({budget.max_files})")

        # Fast pre-pass on declared sizes: catch obvious bombs before writing.
        declared = sum(i.file_size for i in infos)
        compressed = sum(i.compress_size for i in infos)
        if declared > budget.max_total_bytes:
            raise ArchiveBombError("declared uncompressed size exceeds budget")
        if compressed > 0 and declared > _RATIO_FLOOR and declared / compressed > budget.max_ratio:
            raise ArchiveBombError(
                f"compression ratio {declared // max(compressed, 1)} exceeds {budget.max_ratio}"
            )

        for info in infos:
            target = _safe_target(dest, info.filename)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            with zf.open(info) as src, target.open("wb") as dst:
                while chunk := src.read(_CHUNK):
                    written += len(chunk)
                    budget.add_bytes(len(chunk))  # enforces hard cap on lying sizes
                    dst.write(chunk)
            if (
                info.compress_size > 0
                and written > _RATIO_FLOOR
                and written / info.compress_size > budget.max_ratio
            ):
                raise ArchiveBombError("per-file compression ratio exceeds budget")
            budget.add_file()
            results.append(target)


def _extract_tar(archive: Path, dest: Path, budget: _Budget, results: list[Path]) -> None:
    """Extract a TAR with traversal and size guards (no symlink/device entries)."""
    try:
        tf = tarfile.open(archive)  # noqa: SIM115 - closed by the `with` below; try guards open
    except tarfile.TarError as exc:
        raise ArchiveError(f"corrupt tar: {exc}") from exc
    with tf:
        for member in tf:
            if member.isdev() or member.issym() or member.islnk():
                # Special entries are a traversal/foot-gun vector: skip them.
                continue
            target = _safe_target(dest, member.name)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                continue
            written = 0
            with src, target.open("wb") as dst:
                while chunk := src.read(_CHUNK):
                    written += len(chunk)
                    budget.add_bytes(len(chunk))
                    dst.write(chunk)
            budget.add_file()
            results.append(target)


def _extract_7z(archive: Path, dest: Path, budget: _Budget, results: list[Path]) -> None:
    """Extract a 7z archive if it is not encrypted; guard total size."""
    import py7zr

    try:
        sz = py7zr.SevenZipFile(archive, mode="r")
    except py7zr.exceptions.PasswordRequired as exc:
        raise ArchiveError("7z archive is password protected") from exc
    except py7zr.exceptions.Bad7zFile as exc:
        raise ArchiveError(f"corrupt 7z: {exc}") from exc
    with sz:
        if sz.needs_password():
            raise ArchiveError("7z archive is password protected")
        info = sz.archiveinfo()
        if info.uncompressed > budget.max_total_bytes:
            raise ArchiveBombError("declared 7z uncompressed size exceeds budget")
        for name in sz.getnames():
            _safe_target(dest, name)  # traversal check before extraction
        sz.extractall(path=dest)
        for name in sz.getnames():
            target = (dest / name).resolve()
            if target.is_file():
                budget.add_bytes(target.stat().st_size)
                budget.add_file()
                results.append(target)


def _extract_one(archive: Path, dest: Path, budget: _Budget) -> list[Path]:
    """Dispatch to the right extractor based on content sniffing."""
    results: list[Path] = []
    if zipfile.is_zipfile(archive):
        _extract_zip(archive, dest, budget, results)
    elif tarfile.is_tarfile(archive):
        _extract_tar(archive, dest, budget, results)
    else:
        import py7zr

        if py7zr.is_7zfile(archive):
            _extract_7z(archive, dest, budget, results)
        else:
            raise ArchiveError(f"unsupported or unrecognised archive: {archive.name}")
    return results


def safe_extract(
    archive: Path,
    dest: Path,
    *,
    max_depth: int = 5,
    max_total_bytes: int = 4 * 1024**3,
    max_files: int = 10_000,
    max_ratio: int = 200,
) -> list[Path]:
    """Extract with path-traversal and zip-bomb guards. Raises ArchiveBombError.

    Nested archives are recursed into up to ``max_depth`` levels, sharing a
    single byte/file budget so a bomb hidden inside a bomb is still caught.
    """
    dest = dest.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    budget = _Budget(
        max_total_bytes=max_total_bytes,
        max_files=max_files,
        max_ratio=max_ratio,
    )

    all_paths: list[Path] = []
    # (archive_path, dest_dir, depth)
    frontier: list[tuple[Path, Path, int]] = [(archive, dest, 0)]
    while frontier:
        current, current_dest, depth = frontier.pop()
        extracted = _extract_one(current, current_dest, budget)
        all_paths.extend(extracted)
        if depth < max_depth:
            for path in extracted:
                if is_archive(path):
                    nested_dest = path.parent / f"{path.name}.extracted"
                    frontier.append((path, nested_dest, depth + 1))
    return all_paths
