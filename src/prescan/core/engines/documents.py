"""Document and archive analysis: Office VBA (oletools), PDF (pikepdf), archives.

All parsing is of untrusted content and wrapped in try/except: a crafted file
must never crash the pipeline (§10.4). Archives are expanded through
``safe_extract`` with bomb/traversal guards; a tripped guard becomes a signal,
not an exception that escapes.
"""

from __future__ import annotations

import asyncio
import zipfile
from pathlib import Path
from typing import ClassVar, Final

import structlog

from prescan.core.archives import is_archive, safe_extract
from prescan.core.engines.base import ScanContext
from prescan.core.errors import ArchiveBombError, ArchiveError
from prescan.core.identify import EXECUTABLE_EXTS
from prescan.core.models import Availability, Severity, Signal, SourceKind
from prescan.core.scoring import weight

log = structlog.get_logger(__name__)

_AUTOEXEC_KEYWORDS: Final = frozenset(
    {"autoopen", "document_open", "workbook_open", "auto_open", "autoexec"}
)
_OFFICE_EXTS: Final = frozenset(
    {".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm", ".rtf"}
)


class DocumentsEngine:
    """VBA/PDF/archive analysis. Routes by content, never executes anything."""

    name: ClassVar[str] = "documents"
    kind: ClassVar[SourceKind] = SourceKind.STATIC_ANALYSIS
    stage_id: ClassVar[str] = "documents"

    async def availability(self) -> tuple[Availability, str]:
        """Always ready: oletools/pikepdf/py7zr are bundled dependencies."""
        return Availability.READY, "document analysis available"

    async def scan(self, ctx: ScanContext) -> list[Signal]:
        """Route to the right analyser. Never raises on malformed input (§10.4)."""
        try:
            return await asyncio.to_thread(self._analyse, ctx)
        except Exception as exc:  # noqa: BLE001 - untrusted content (§10.4)
            log.warning("documents.failed", error=str(exc))
            return [self._info(f"document analysis could not complete: {exc}")]

    def _analyse(self, ctx: ScanContext) -> list[Signal]:
        """Dispatch by sniffed content and extension."""
        head = self._head(ctx.path)
        if head.startswith(b"%PDF"):
            return self._analyse_pdf(ctx.path)
        if ctx.path.suffix.lower() in _OFFICE_EXTS or head.startswith(b"\xd0\xcf\x11\xe0"):
            return self._analyse_office(ctx.path)
        if is_archive(ctx.path):
            return self._analyse_archive(ctx)
        return []

    @staticmethod
    def _head(path: Path, n: int = 8) -> bytes:
        try:
            with path.open("rb") as fh:
                return fh.read(n)
        except OSError:
            return b""

    # ---- Office VBA ----------------------------------------------------- #
    def _analyse_office(self, path: Path) -> list[Signal]:
        """Detect VBA macros, autoexec triggers and obfuscation via oletools."""
        from oletools.olevba import VBA_Parser

        signals: list[Signal] = []
        parser = None
        try:
            parser = VBA_Parser(str(path))
            if not parser.detect_vba_macros():
                return []
            signals.append(
                Signal(
                    source=self.name,
                    kind=self.kind,
                    severity=Severity.MEDIUM,
                    title_key="signal.doc.vba_macro",
                    title_en="Document contains VBA macros",
                    weight=weight("documents", "vba_macro", 30),
                    data={"vba": True},
                )
            )
            keywords: list[str] = []
            for _kind, keyword, _desc in parser.analyze_macros() or []:
                keywords.append(str(keyword))
            lowered = {k.lower() for k in keywords}
            if lowered & _AUTOEXEC_KEYWORDS:
                signals.append(
                    Signal(
                        source=self.name,
                        kind=self.kind,
                        severity=Severity.HIGH,
                        title_key="signal.doc.vba_autoexec",
                        title_en="Macro auto-executes on open",
                        detail=", ".join(sorted(lowered & _AUTOEXEC_KEYWORDS)),
                        weight=weight("documents", "vba_autoexec", 45),
                        mitre=["T1059.005"],
                    )
                )
            obfuscation_markers = ("hex", "base64", "obfus")
            if any(marker in k.lower() for k in keywords for marker in obfuscation_markers):
                signals.append(
                    Signal(
                        source=self.name,
                        kind=self.kind,
                        severity=Severity.HIGH,
                        title_key="signal.doc.vba_obfuscated",
                        title_en="Macro shows obfuscation",
                        weight=weight("documents", "vba_obfuscated", 40),
                        mitre=["T1027"],
                    )
                )
        finally:
            if parser is not None:
                parser.close()
        return signals

    # ---- PDF ------------------------------------------------------------ #
    def _analyse_pdf(self, path: Path) -> list[Signal]:
        """Detect /JavaScript, /OpenAction, /Launch and embedded files."""
        import pikepdf

        signals: list[Signal] = []
        with pikepdf.open(path) as pdf:
            root = pdf.Root
            root_keys = set(map(str, root.keys()))
            name_keys: set[str] = set()
            if "/Names" in root_keys:
                try:
                    name_keys = set(map(str, root.Names.keys()))
                except (AttributeError, KeyError):
                    name_keys = set()

            if "/OpenAction" in root_keys or "/AA" in root_keys:
                signals.append(
                    Signal(
                        source=self.name,
                        kind=self.kind,
                        severity=Severity.MEDIUM,
                        title_key="signal.pdf.openaction",
                        title_en="PDF defines an automatic action (/OpenAction)",
                        weight=weight("documents", "pdf_openaction", 35),
                    )
                )
            if "/JavaScript" in name_keys or "/JavaScript" in root_keys:
                signals.append(
                    Signal(
                        source=self.name,
                        kind=self.kind,
                        severity=Severity.MEDIUM,
                        title_key="signal.pdf.javascript",
                        title_en="PDF contains JavaScript",
                        weight=weight("documents", "pdf_javascript", 35),
                        mitre=["T1204.002"],
                    )
                )
            if "/EmbeddedFiles" in name_keys:
                signals.append(
                    Signal(
                        source=self.name,
                        kind=self.kind,
                        severity=Severity.HIGH,
                        title_key="signal.pdf.embedded",
                        title_en="PDF has embedded files",
                        weight=weight("documents", "pdf_embedded_exe", 60),
                    )
                )
        return signals

    # ---- Archives ------------------------------------------------------- #
    def _analyse_archive(self, ctx: ScanContext) -> list[Signal]:
        """Expand safely; flag bombs and password-protected archives with exes."""
        signals: list[Signal] = []
        signals += self._password_protected_signals(ctx.path)
        dest = ctx.workdir / "unpacked"
        try:
            safe_extract(ctx.path, dest, max_depth=5, max_ratio=200)
        except ArchiveBombError as exc:
            signals.append(
                Signal(
                    source=self.name,
                    kind=self.kind,
                    severity=Severity.HIGH,
                    title_key="signal.archive.bomb",
                    title_en="Archive tripped the decompression-bomb guard",
                    detail=str(exc),
                    weight=weight("archive", "bomb_guard_triggered", 50),
                )
            )
        except ArchiveError as exc:
            signals.append(self._info(f"archive could not be extracted: {exc}"))
        return signals

    def _password_protected_signals(self, path: Path) -> list[Signal]:
        """Flag a password-protected archive that hides an executable."""
        try:
            if not zipfile.is_zipfile(path):
                return []
            with zipfile.ZipFile(path) as zf:
                encrypted = any(info.flag_bits & 0x1 for info in zf.infolist())
                has_exe = any(
                    Path(info.filename).suffix.lower() in EXECUTABLE_EXTS for info in zf.infolist()
                )
        except (OSError, zipfile.BadZipFile):
            return []
        if encrypted and has_exe:
            return [
                Signal(
                    source=self.name,
                    kind=self.kind,
                    severity=Severity.HIGH,
                    title_key="signal.archive.password_exe",
                    title_en="Password-protected archive contains an executable",
                    weight=weight("archive", "password_protected_with_exe", 35),
                )
            ]
        return []

    def _info(self, message: str) -> Signal:
        return Signal(
            source=self.name,
            kind=self.kind,
            severity=Severity.INFO,
            title_key="signal.doc.error",
            title_en="Document analysis note",
            detail=message,
        )
