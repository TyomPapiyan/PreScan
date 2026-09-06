"""The main result of stage H: real clean system files of many types must never be
flagged SUSPICIOUS or DANGEROUS.

This is the guard that a green unit suite could not provide -- it was one real
`prescan scan README.md` that exposed the ML false positive on non-executables, and
this test runs the WHOLE pipeline over a spread of clean system files (executables,
text, images, archives, documents) and fails if any comes back SUSPICIOUS/DANGEROUS.

Files are taken from the machine at run time, never committed. A type with no sample
on this platform is skipped with a note (recorded in ``covered``), not silently
dropped. It runs on Linux and Windows; the network is off, so no source leaves the
machine. The ML false positive is only reachable when a real ``model.onnx`` is
installed (CI downloads it); without a model the ml stage is simply NO_MODEL.
"""

from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from prescan.core.config import AppConfig
from prescan.core.models import ScanReport, ScanRequest, TargetKind, Verdict
from prescan.core.pipeline import Pipeline

_IS_WINDOWS = sys.platform == "win32"

# Platform-appropriate roots to look under (shallow, fast).
_ROOTS = (
    [r"C:\Windows\System32", r"C:\Windows", r"C:\Program Files"]
    if _IS_WINDOWS
    else ["/usr/bin", "/usr/share/icons", "/usr/share/doc", "/usr/lib", "/usr/share", "/etc"]
)


def _matches_executable(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            head = fh.read(4)
    except OSError:
        return False
    return head[:2] == b"MZ" or head[:4] == b"\x7fELF"


def _suffix_match(suffixes: set[str]) -> Callable[[Path], bool]:
    def match(path: Path) -> bool:
        return path.suffix.lower() in suffixes

    return match


def _collect(
    match: Callable[[Path], bool], *, limit: int, maxdepth: int = 3, min_size: int = 64
) -> list[Path]:
    """Collect up to ``limit`` files satisfying ``match``, shallow and early-stopping."""
    out: list[Path] = []
    for root in _ROOTS:
        base = Path(root)
        if not base.is_dir():
            continue
        base_depth = len(base.parts)
        for dirpath, dirnames, filenames in os.walk(base):
            if len(Path(dirpath).parts) - base_depth >= maxdepth:
                dirnames[:] = []  # do not descend further
            for name in filenames:
                p = Path(dirpath) / name
                try:
                    if p.is_symlink() or not p.is_file() or p.stat().st_size < min_size:
                        continue
                except OSError:
                    continue
                if match(p):
                    out.append(p)
                    if len(out) >= limit:
                        return out
    return out


# Clean files of every type -- executables, text, images, archives AND documents --
# must never be SUSPICIOUS or DANGEROUS. Documents are back under the strict rule (§I):
# a bare /OpenAction is informational now, so a plain PDF no longer false-positives.
_CORPUS = {
    "executable (PE/ELF)": _matches_executable,
    "text": _suffix_match({".txt", ".md", ".conf", ".cfg", ".ini"}),
    "json": _suffix_match({".json"}),
    "PNG": _suffix_match({".png"}),
    "JPEG": _suffix_match({".jpg", ".jpeg"}),
    "archive": _suffix_match({".zip", ".whl", ".jar", ".gz", ".xz"}),
    "PDF": _suffix_match({".pdf"}),
}


async def _scan(config: AppConfig, path: Path) -> ScanReport:
    request = ScanRequest(
        target_kind=TargetKind.FILE, file_path=path, allow_network=False, force_refresh=True
    )
    return await Pipeline(config).run(request)


def _no_ml_probability(report: ScanReport) -> bool:
    """True if the report carries no ML probability signal (stage removed by type)."""
    return not any(s.source == "ml" and "probability" in s.data for s in report.signals)


@pytest.mark.asyncio
async def test_clean_system_files_are_never_flagged() -> None:
    config = AppConfig.load()
    config.allow_network = False  # nothing leaves the machine

    covered: dict[str, int] = {}
    flagged: list[str] = []
    scanned = 0

    for label, match in _CORPUS.items():
        files = _collect(match, limit=2)
        covered[label] = len(files)
        is_executable = label.startswith("executable")
        for path in files:
            scanned += 1
            try:
                report = await _scan(config, path)
            except Exception as exc:  # noqa: BLE001 - a crash on a clean file is a failure
                flagged.append(f"{label}: {path} -> raised {exc!r}")
                continue
            # Strict (§I): a clean file of any type must be neither SUSPICIOUS nor DANGEROUS.
            if report.verdict in (Verdict.SUSPICIOUS, Verdict.DANGEROUS):
                reasons = ", ".join(
                    s.title_en for s in report.signals if s.data.get("escalates") or s.decisive
                )
                flagged.append(f"{label}: {path} -> {report.verdict.value} ({reasons})")
            # A non-executable must carry no ML probability at all (stage removed by type).
            # With a model installed (CI) this proves the number never reaches the report;
            # without one the ml stage is simply NO_MODEL.
            if not is_executable and not _no_ml_probability(report):
                flagged.append(f"{label}: {path} carried an ML probability")

    print(f"clean-corpus coverage (found per type): {covered}")
    # Not vacuous: at least executables plus one data type must have been available.
    assert scanned >= 3, f"too few clean files found to be meaningful: {covered}"
    assert covered["executable (PE/ELF)"] > 0, "no executable sample found to scan"
    assert any(covered[t] > 0 for t in ("text", "json", "PNG", "JPEG", "archive", "PDF")), (
        "no non-executable data file found to scan -- the false-positive case is untested"
    )
    assert not flagged, "clean files were flagged:\n" + "\n".join(flagged)


if __name__ == "__main__":  # pragma: no cover - manual corpus inspection
    asyncio.run(test_clean_system_files_are_never_flagged())
