"""Scan pipeline orchestrator: progress streaming and cancellation.

Implements the file pipeline of §6 for stages 1-10: identify, hash, cache,
signature, then the local engines (clamav, yara, defender, static, documents,
ml) run concurrently and collected in a fixed order, then scoring. No source is
allowed to break the run: unavailable engines are SKIPPED and recorded in
``unavailable_sources`` with ``incomplete=True`` (§6.1).

Reputation, capa and cloud upload (stages 11-13) arrive on later milestones.
"""

from __future__ import annotations

import asyncio
import contextlib
import shutil
import tempfile
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import structlog

from prescan.core.config import AppConfig, Paths
from prescan.core.engines import build_engines
from prescan.core.engines.base import Engine, ScanContext
from prescan.core.errors import EngineSkipped
from prescan.core.hashing import fuzzy_hash, hash_file, imphash
from prescan.core.identify import identify
from prescan.core.models import (
    Availability,
    FileInfo,
    ScanReport,
    ScanRequest,
    Severity,
    Signal,
    SourceKind,
    StageResult,
    StageStatus,
    TargetKind,
    Verdict,
)
from prescan.core.scoring import score, weight
from prescan.core.signature import get_signature, signature_signals

log = structlog.get_logger(__name__)

OnStage = Callable[[StageResult], None]

#: Engines whose completion counts as an authoritative clean/dirty verdict (§8.3).
_AUTHORITATIVE = frozenset({"clamav", "defender"})


class Pipeline:
    """Runs the full analysis pipeline for one request."""

    def __init__(self, config: AppConfig, storage: object | None = None) -> None:
        self._config = config
        self._storage = storage  # SQLite cache/history arrives on M2
        self._paths = Paths.resolve()

    async def run(
        self,
        request: ScanRequest,
        *,
        on_stage: OnStage | None = None,
        cancel: asyncio.Event | None = None,
    ) -> ScanReport:
        """Execute the full pipeline. on_stage is called on every status change."""
        if request.target_kind is not TargetKind.FILE:
            raise NotImplementedError("URL scanning lands on M3")
        assert request.file_path is not None
        cancel = cancel or asyncio.Event()
        started = datetime.now(UTC)
        scan_id = uuid.uuid4().hex

        self._paths.ensure()
        workdir = Path(tempfile.mkdtemp(prefix="prescan-scan-", dir=self._paths.tmp_dir))
        with contextlib.suppress(OSError):  # pragma: no cover - platform dependent
            workdir.chmod(0o700)

        stages: list[StageResult] = []
        signals: list[Signal] = []
        unavailable: list[str] = []

        try:
            file_info = await self._collect_file_info(request.file_path, stages, on_stage)
            signals += self._identify_signals(file_info)
            signals += signature_signals(file_info.signature) if file_info.signature else []

            had_authoritative = False
            if not cancel.is_set():
                engine_signals, had_authoritative = await self._run_engines(
                    file_info, workdir, request, stages, unavailable, on_stage, cancel
                )
                signals += engine_signals

            verdict, risk, reason_key, reason_en = self._score(
                signals, had_authoritative=had_authoritative, cancelled=cancel.is_set()
            )
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

        finished = datetime.now(UTC)
        report = ScanReport(
            scan_id=scan_id,
            app_version=_app_version(),
            request=request,
            started_at=started,
            finished_at=finished,
            duration_s=(finished - started).total_seconds(),
            file=file_info,
            signals=signals,
            stages=stages,
            verdict=verdict,
            risk_score=risk,
            verdict_reason_key=reason_key,
            verdict_reason_en=reason_en,
            incomplete=bool(unavailable) or cancel.is_set(),
            unavailable_sources=unavailable,
        )
        return report

    # ------------------------------------------------------------------ #
    # Stages 1-4: identify, hash, cache, signature
    # ------------------------------------------------------------------ #
    async def _collect_file_info(
        self,
        path: Path,
        stages: list[StageResult],
        on_stage: OnStage | None,
    ) -> FileInfo:
        """Run stages 1-4 and assemble the FileInfo record."""
        resolved = path.resolve()
        size = resolved.stat().st_size
        declared_ext = resolved.suffix.lower()

        # Stage 1: identify
        with self._stage("identify", "stage.identify", stages, on_stage) as st:
            detected_type, detected_mime, mismatch = identify(resolved)
            st.summary = detected_type

        # Stage 2: hashing. These stages are cheap and needed for the report and
        # cache key, so they always complete; cancellation aborts the engine phase.
        with self._stage("hashing", "stage.hashing", stages, on_stage) as st:
            digests = await hash_file(resolved)
            imp = await asyncio.to_thread(_safe_imphash, resolved)
            fuzzy = await asyncio.to_thread(fuzzy_hash, resolved)
            st.summary = f"sha256:{digests['sha256'][:12]}"

        # Stage 3: cache (SQLite lands on M2)
        with self._stage("cache", "stage.cache", stages, on_stage) as st:
            st.status = StageStatus.SKIPPED
            st.availability = Availability.DISABLED
            st.summary = "cache not enabled yet"

        # Stage 4: signature
        with self._stage("signature", "stage.signature", stages, on_stage) as st:
            sig = await asyncio.to_thread(get_signature, resolved)
            st.summary = "present" if sig.present else "absent"

        return FileInfo(
            path=resolved,
            name=resolved.name,
            size=size,
            declared_extension=declared_ext,
            detected_type=detected_type,
            detected_mime=detected_mime,
            extension_mismatch=mismatch,
            md5=digests["md5"],
            sha1=digests["sha1"],
            sha256=digests["sha256"],
            imphash=imp,
            ssdeep=fuzzy,
            signature=sig,
        )

    def _identify_signals(self, info: FileInfo) -> list[Signal]:
        """Emit a signal for a detected extension mismatch (§8.2)."""
        if not info.extension_mismatch:
            return []
        return [
            Signal(
                source="identify",
                kind=SourceKind.STATIC_ANALYSIS,
                severity=Severity.MEDIUM,
                title_key="signal.identify.extension_mismatch",
                title_en="File type does not match its extension",
                detail=f"{info.declared_extension} vs {info.detected_type}",
                weight=weight("static", "extension_mismatch", 40),
                data={"declared": info.declared_extension, "detected": info.detected_type},
            )
        ]

    # ------------------------------------------------------------------ #
    # Stages 5-10: local engines, concurrent, collected in order
    # ------------------------------------------------------------------ #
    async def _run_engines(
        self,
        info: FileInfo,
        workdir: Path,
        request: ScanRequest,
        stages: list[StageResult],
        unavailable: list[str],
        on_stage: OnStage | None,
        cancel: asyncio.Event,
    ) -> tuple[list[Signal], bool]:
        """Probe and run every engine concurrently; collect signals in order."""
        engines = build_engines(self._config, self._paths)

        # Availability probe (cheap) decides which engines actually run.
        runnable: list[Engine] = []
        for engine in engines:
            if not self._config.engine_enabled(engine.name):
                self._skip_stage(engine, Availability.DISABLED, "disabled", stages, on_stage)
                unavailable.append(engine.name)
                continue
            availability, detail = await engine.availability()
            if availability is Availability.READY:
                runnable.append(engine)
            else:
                self._skip_stage(engine, availability, detail, stages, on_stage)
                unavailable.append(engine.name)

        # Mark runnable engines RUNNING before launching them.
        stage_by_name: dict[str, StageResult] = {}
        for engine in runnable:
            st = StageResult(
                stage_id=engine.stage_id,
                title_key=f"stage.{engine.stage_id}",
                status=StageStatus.RUNNING,
                started_at=datetime.now(UTC),
            )
            stages.append(st)
            stage_by_name[engine.name] = st
            _notify(on_stage, st)

        async def run_one(engine: Engine) -> list[Signal]:
            ctx = ScanContext(
                path=info.path,
                info=info,
                cancel=cancel,
                timeout_s=request.timeout_s,
                workdir=workdir / engine.name,
            )
            ctx.workdir.mkdir(parents=True, exist_ok=True)
            return await engine.scan(ctx)

        results = await asyncio.gather(
            *(run_one(engine) for engine in runnable), return_exceptions=True
        )

        collected: list[Signal] = []
        had_authoritative = False
        for engine, outcome in zip(runnable, results, strict=True):
            st = stage_by_name[engine.name]
            st.finished_at = datetime.now(UTC)
            if st.started_at is not None:
                st.duration_s = (st.finished_at - st.started_at).total_seconds()

            if isinstance(outcome, EngineSkipped):
                st.status = StageStatus.SKIPPED
                st.availability = Availability(outcome.availability)
                st.summary = outcome.summary
                unavailable.append(engine.name)
            elif isinstance(outcome, BaseException):
                st.status = StageStatus.FAILED
                st.error = str(outcome)
                unavailable.append(engine.name)
                log.warning("engine.failed", engine=engine.name, error=str(outcome))
            else:
                st.status = StageStatus.DONE
                st.summary = _summarise(outcome)
                collected.extend(outcome)
                if engine.name in _AUTHORITATIVE:
                    had_authoritative = True
            _notify(on_stage, st)

        return collected, had_authoritative

    # ------------------------------------------------------------------ #
    # Scoring
    # ------------------------------------------------------------------ #
    def _score(
        self, signals: list[Signal], *, had_authoritative: bool, cancelled: bool
    ) -> tuple[Verdict, int, str, str]:
        """Run the scoring stage; a cancelled scan is always UNKNOWN."""
        if cancelled:
            return (Verdict.UNKNOWN, 0, "verdict.cancelled", "Scan cancelled by the user")
        return score(signals, had_authoritative_source=had_authoritative)

    # ------------------------------------------------------------------ #
    # Stage helpers
    # ------------------------------------------------------------------ #
    def _stage(
        self,
        stage_id: str,
        title_key: str,
        stages: list[StageResult],
        on_stage: OnStage | None,
    ) -> _StageScope:
        return _StageScope(stage_id, title_key, stages, on_stage)

    def _skip_stage(
        self,
        engine: Engine,
        availability: Availability,
        detail: str,
        stages: list[StageResult],
        on_stage: OnStage | None,
    ) -> None:
        st = StageResult(
            stage_id=engine.stage_id,
            title_key=f"stage.{engine.stage_id}",
            status=StageStatus.SKIPPED,
            availability=availability,
            summary=detail,
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
        )
        stages.append(st)
        _notify(on_stage, st)


class _StageScope:
    """Context manager that records a stage's timing and status."""

    def __init__(
        self,
        stage_id: str,
        title_key: str,
        stages: list[StageResult],
        on_stage: OnStage | None,
    ) -> None:
        self.result = StageResult(stage_id=stage_id, title_key=title_key)
        self._stages = stages
        self._on_stage = on_stage

    def __enter__(self) -> StageResult:
        self.result.status = StageStatus.RUNNING
        self.result.started_at = datetime.now(UTC)
        _notify(self._on_stage, self.result)
        return self.result

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.result.finished_at = datetime.now(UTC)
        if self.result.started_at is not None:
            self.result.duration_s = (
                self.result.finished_at - self.result.started_at
            ).total_seconds()
        if exc_type is not None:
            self.result.status = StageStatus.FAILED
            self.result.error = str(exc)
        elif self.result.status is StageStatus.RUNNING:
            self.result.status = StageStatus.DONE
        self._stages.append(self.result)
        _notify(self._on_stage, self.result)


def _notify(on_stage: OnStage | None, stage: StageResult) -> None:
    """Call the progress callback, ignoring any error it raises."""
    if on_stage is None:
        return
    try:
        on_stage(stage.model_copy(deep=True))
    except Exception:  # noqa: BLE001 - a bad UI callback must not break a scan
        log.debug("on_stage.callback_failed", stage=stage.stage_id)


def _safe_imphash(path: Path) -> str | None:
    """Parse with LIEF and return the imphash, or None. Never raises."""
    try:
        import lief

        binary = lief.parse(str(path))
        if not isinstance(binary, lief.PE.Binary):
            return None
        return imphash(binary)
    except Exception:  # noqa: BLE001 - untrusted binary (§10.4)
        return None


def _summarise(signals: list[Signal]) -> str:
    """One-line summary of an engine's output for the stage row."""
    if not signals:
        return "clean"
    return f"{len(signals)} signal(s)"


def _app_version() -> str:
    """Return the running app version."""
    from prescan import __version__

    return __version__
