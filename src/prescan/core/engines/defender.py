"""Microsoft Defender engine via MpCmdRun.exe (Windows only).

On any non-Windows host the engine reports ``UNSUPPORTED_OS`` and is skipped —
that is the expected outcome on this Linux deployment, not an error. On Windows
it invokes the documented offline scan with remediation disabled, passing the
scanned file strictly as a path argument, never executing it (§10.3).
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
from pathlib import Path
from typing import ClassVar

import structlog

from prescan.core.engines.base import ScanContext
from prescan.core.models import Availability, Severity, Signal, SourceKind
from prescan.core.scoring import weight

log = structlog.get_logger(__name__)


def _find_mpcmdrun() -> Path | None:
    """Locate MpCmdRun.exe on Windows, or return None."""
    on_path = shutil.which("MpCmdRun.exe")
    if on_path:
        return Path(on_path)
    program_data = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
    platform_root = Path(program_data) / "Microsoft" / "Windows Defender" / "Platform"
    if platform_root.is_dir():
        candidates = sorted(platform_root.glob("*/MpCmdRun.exe"), reverse=True)
        if candidates:
            return candidates[0]
    return None


class DefenderEngine:
    """Microsoft Defender command-line scan. Windows only."""

    name: ClassVar[str] = "defender"
    kind: ClassVar[SourceKind] = SourceKind.LOCAL_ENGINE
    stage_id: ClassVar[str] = "defender"

    async def availability(self) -> tuple[Availability, str]:
        """UNSUPPORTED_OS off Windows; NOT_INSTALLED if the tool is missing."""
        if not sys.platform.startswith("win"):
            return Availability.UNSUPPORTED_OS, "Microsoft Defender is Windows-only"
        if _find_mpcmdrun() is None:
            return Availability.NOT_INSTALLED, "MpCmdRun.exe not found"
        return Availability.READY, "Microsoft Defender available"

    async def scan(self, ctx: ScanContext) -> list[Signal]:
        """Run an offline Defender scan of the file. Never raises (§10.4)."""
        exe = _find_mpcmdrun()
        if exe is None:  # pragma: no cover - guarded by availability()
            return []
        try:
            proc = await asyncio.create_subprocess_exec(
                str(exe),
                "-Scan",
                "-ScanType",
                "3",
                "-File",
                str(ctx.path),
                "-DisableRemediation",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=ctx.timeout_s)
        except (TimeoutError, OSError) as exc:  # pragma: no cover - Windows path
            log.warning("defender.scan_failed", error=str(exc))
            return [
                Signal(
                    source=self.name,
                    kind=self.kind,
                    severity=Severity.INFO,
                    title_key="signal.defender.error",
                    title_en="Microsoft Defender scan could not complete",
                    detail=str(exc),
                )
            ]

        # MpCmdRun returns non-zero and prints the threat name when it finds one.
        output = stdout.decode("utf-8", "replace")
        if proc.returncode and "Threat" in output:  # pragma: no cover - Windows path
            return [
                Signal(
                    source=self.name,
                    kind=self.kind,
                    severity=Severity.CRITICAL,
                    title_key="signal.defender.found",
                    title_en="Microsoft Defender detection",
                    detail=output.strip()[:500],
                    weight=weight("local_engine", "defender_detection", 100),
                    decisive=True,
                    data={"returncode": proc.returncode},
                )
            ]
        return []
