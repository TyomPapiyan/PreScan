"""LIEF-based static analysis: section entropy, imports, TLS callbacks, overlay.

Only PE binaries are analysed here; other formats yield no signals. LIEF parses
untrusted input, so the whole body is wrapped in try/except and any failure
becomes a single INFO signal (§10.4). LIEF is used for static analysis only —
never for ML features (§3.4).
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, ClassVar, Final

import structlog

from prescan.core.engines.base import ScanContext
from prescan.core.models import Availability, Severity, Signal, SourceKind
from prescan.core.scoring import weight

if TYPE_CHECKING:
    import lief

log = structlog.get_logger(__name__)

_ENTROPY_THRESHOLD: Final = 7.2
#: Classic process-injection import triple (§8.4 injection_imports).
_INJECTION_IMPORTS: Final = frozenset(
    {"virtualalloc", "virtualallocex", "writeprocessmemory", "createremotethread"}
)
_OVERLAY_MIN: Final = 1024 * 1024  # 1 MiB overlay counts as "large"


class StaticPEEngine:
    """Structural analysis of PE files via LIEF."""

    name: ClassVar[str] = "static-pe"
    kind: ClassVar[SourceKind] = SourceKind.STATIC_ANALYSIS
    stage_id: ClassVar[str] = "static"

    async def availability(self) -> tuple[Availability, str]:
        """Always ready: LIEF is a bundled dependency."""
        return Availability.READY, "static analysis available"

    async def scan(self, ctx: ScanContext) -> list[Signal]:
        """Analyse the file. Never raises on malformed input (§10.4)."""
        try:
            return await asyncio.to_thread(self._analyse, ctx)
        except Exception as exc:  # noqa: BLE001 - untrusted binary (§10.4)
            log.warning("static_pe.failed", error=str(exc))
            return [
                Signal(
                    source=self.name,
                    kind=self.kind,
                    severity=Severity.INFO,
                    title_key="signal.static.error",
                    title_en="Static analysis could not parse the file",
                    detail=str(exc),
                )
            ]

    def _analyse(self, ctx: ScanContext) -> list[Signal]:
        """Synchronous LIEF analysis body executed in a worker thread."""
        import lief

        binary = lief.parse(str(ctx.path))
        if not isinstance(binary, lief.PE.Binary):
            return []

        signals: list[Signal] = []
        signals += self._entropy_signals(binary)
        signals += self._import_signals(binary)
        signals += self._tls_signals(binary)
        signals += self._overlay_signals(binary)
        return signals

    def _entropy_signals(self, binary: lief.PE.Binary) -> list[Signal]:
        """Flag a high-entropy executable section (a packing indicator)."""
        peak = 0.0
        peak_name = ""
        for section in binary.sections:
            try:
                entropy = float(section.entropy)
            except (TypeError, ValueError):
                continue
            if entropy > peak:
                peak, peak_name = entropy, str(section.name)
        if peak > _ENTROPY_THRESHOLD:
            return [
                Signal(
                    source=self.name,
                    kind=self.kind,
                    severity=Severity.MEDIUM,
                    title_key="signal.static.high_entropy",
                    title_en=f"High-entropy section {peak_name} ({peak:.2f})",
                    detail=f"{peak_name}: {peak:.2f}",
                    weight=weight("static", "high_entropy_unsigned", 30),
                    data={"section": peak_name, "entropy": peak, "packing_only": True},
                )
            ]
        return []

    def _import_signals(self, binary: lief.PE.Binary) -> list[Signal]:
        """Flag the process-injection import triple."""
        names = set()
        try:
            names = {fn.name.lower() for fn in binary.imported_functions if fn.name}
        except Exception:  # noqa: BLE001 - some PEs have no import table
            return []
        if names >= _INJECTION_IMPORTS or (
            "virtualalloc" in names
            and "writeprocessmemory" in names
            and "createremotethread" in names
        ):
            return [
                Signal(
                    source=self.name,
                    kind=self.kind,
                    severity=Severity.HIGH,
                    title_key="signal.static.injection_imports",
                    title_en="Process-injection imports present",
                    detail="VirtualAlloc + WriteProcessMemory + CreateRemoteThread",
                    weight=weight("static", "injection_imports", 35),
                    mitre=["T1055"],
                    data={"imports": sorted(_INJECTION_IMPORTS & names)},
                )
            ]
        return []

    def _tls_signals(self, binary: lief.PE.Binary) -> list[Signal]:
        """Flag the presence of TLS callbacks (can run code before main)."""
        try:
            tls = binary.tls
            callbacks = list(tls.callbacks) if tls is not None else []
        except Exception:  # noqa: BLE001 - TLS directory may be malformed
            return []
        if callbacks:
            return [
                Signal(
                    source=self.name,
                    kind=self.kind,
                    severity=Severity.LOW,
                    title_key="signal.static.tls_callbacks",
                    title_en="TLS callbacks present",
                    detail=f"{len(callbacks)} callback(s)",
                    weight=weight("static", "tls_callbacks", 15),
                )
            ]
        return []

    def _overlay_signals(self, binary: lief.PE.Binary) -> list[Signal]:
        """Flag a large overlay (data appended after the PE image)."""
        try:
            overlay_size = len(bytes(binary.overlay))
        except Exception:  # noqa: BLE001 - overlay access may fail
            return []
        if overlay_size >= _OVERLAY_MIN:
            return [
                Signal(
                    source=self.name,
                    kind=self.kind,
                    severity=Severity.LOW,
                    title_key="signal.static.large_overlay",
                    title_en=f"Large overlay ({overlay_size} bytes)",
                    detail=f"{overlay_size} bytes",
                    weight=weight("static", "large_overlay", 10),
                    data={"overlay_size": overlay_size},
                )
            ]
        return []
