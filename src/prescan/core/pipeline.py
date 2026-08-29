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
    UrlInfo,
    Verdict,
)
from prescan.core.providers import build_hash_providers, build_url_providers
from prescan.core.providers.base import Provider
from prescan.core.ratelimit import RateLimiter
from prescan.core.scoring import score, weight
from prescan.core.signature import get_signature, signature_signals
from prescan.core.storage import Storage
from prescan.core.url import heuristics as url_heuristics
from prescan.core.url import normalize as url_normalize
from prescan.core.url.downloader import safe_download
from prescan.core.url.inspector import inspect as inspect_url
from prescan.core.url.rdap import domain_age_days
from prescan.core.url.tls import inspect_tls

log = structlog.get_logger(__name__)

OnStage = Callable[[StageResult], None]

#: Engines whose completion counts as an authoritative clean/dirty verdict (§8.3).
_AUTHORITATIVE = frozenset({"clamav", "defender"})


class Pipeline:
    """Runs the full analysis pipeline for one request."""

    def __init__(self, config: AppConfig, storage: Storage | None = None) -> None:
        self._config = config
        self._storage = storage
        self._paths = Paths.resolve()
        self._limiter = RateLimiter()

    async def run(
        self,
        request: ScanRequest,
        *,
        on_stage: OnStage | None = None,
        cancel: asyncio.Event | None = None,
    ) -> ScanReport:
        """Execute the full pipeline. on_stage is called on every status change."""
        cancel = cancel or asyncio.Event()
        if request.target_kind is TargetKind.URL:
            return await self._run_url(request, on_stage=on_stage, cancel=cancel)
        assert request.file_path is not None
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

            # Stage 3: cache. A fresh hit short-circuits the pipeline (§6).
            cached = await self._check_cache(file_info, request, stages, on_stage)
            if cached is not None:
                self._save_history(cached)
                return cached

            signals += self._identify_signals(file_info)
            signals += signature_signals(file_info.signature) if file_info.signature else []

            had_authoritative = False
            if not cancel.is_set():
                engine_signals, had_authoritative = await self._run_engines(
                    file_info, workdir, request, stages, unavailable, on_stage, cancel
                )
                signals += engine_signals

                # Stage 11: reputation by hash (only the hash leaves, §6.2).
                if request.allow_network and self._config.allow_network:
                    rep_signals, rep_authoritative = await self._run_providers(
                        file_info, request, stages, unavailable, on_stage, cancel
                    )
                    signals += rep_signals
                    had_authoritative = had_authoritative or rep_authoritative

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

        # Persist a completed, non-cached scan to cache and history.
        if not cancel.is_set():
            await self._save_report(report)
        return report

    # ------------------------------------------------------------------ #
    # Stage 3: cache; persistence
    # ------------------------------------------------------------------ #
    async def _check_cache(
        self,
        file_info: FileInfo,
        request: ScanRequest,
        stages: list[StageResult],
        on_stage: OnStage | None,
    ) -> ScanReport | None:
        """Return a fresh cached report (from_cache=True) or None, recording the stage."""
        with self._stage("cache", "stage.cache", stages, on_stage) as st:
            if self._storage is None or request.force_refresh:
                st.status = StageStatus.SKIPPED
                st.availability = Availability.DISABLED
                st.summary = "cache bypassed" if request.force_refresh else "cache disabled"
                return None
            cached = await asyncio.to_thread(
                self._storage.get_cached,
                file_info.sha256,
                ttl_days=self._config.cache_ttl_days,
            )
            if cached is None:
                st.summary = "miss"
                return None
            st.summary = "hit"
            return cached

    async def _save_report(self, report: ScanReport) -> None:
        """Store the report in the cache and history (best effort)."""
        if self._storage is None:
            return
        await asyncio.to_thread(self._storage.put_cache, report)
        await asyncio.to_thread(self._storage.add_history, report)

    def _save_history(self, report: ScanReport) -> None:
        """Record a cache-hit scan in history without re-caching it."""
        if self._storage is not None:
            self._storage.add_history(report)

    # ------------------------------------------------------------------ #
    # Stages 1-4: identify, hash, signature
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
    # Stage 11: cloud reputation by hash (only the SHA-256 leaves, §6.2)
    # ------------------------------------------------------------------ #
    async def _run_providers(
        self,
        info: FileInfo,
        request: ScanRequest,
        stages: list[StageResult],
        unavailable: list[str],
        on_stage: OnStage | None,
        cancel: asyncio.Event,
    ) -> tuple[list[Signal], bool]:
        """Query hash-reputation providers concurrently; collect signals in order."""
        providers = build_hash_providers(
            self._limiter, allow_network=request.allow_network and self._config.allow_network
        )

        runnable: list[Provider] = []
        for provider in providers:
            availability, detail = await provider.availability()
            if availability is Availability.READY:
                runnable.append(provider)
            else:
                self._skip_named(provider.name, availability, detail, stages, unavailable, on_stage)

        stage_by_name: dict[str, StageResult] = {}
        for provider in runnable:
            st = StageResult(
                stage_id=provider.name,
                title_key="stage.reputation",
                status=StageStatus.RUNNING,
                started_at=datetime.now(UTC),
            )
            stages.append(st)
            stage_by_name[provider.name] = st
            _notify(on_stage, st)

        async def run_one(provider: Provider) -> list[Signal]:
            try:
                return await provider.lookup_hash(info.sha256)
            except Exception as exc:
                log.warning("provider.failed", provider=provider.name, error=str(exc))
                raise

        results = await asyncio.gather(
            *(run_one(provider) for provider in runnable), return_exceptions=True
        )

        collected: list[Signal] = []
        had_authoritative = False
        for provider, outcome in zip(runnable, results, strict=True):
            st = stage_by_name[provider.name]
            st.finished_at = datetime.now(UTC)
            if st.started_at is not None:
                st.duration_s = (st.finished_at - st.started_at).total_seconds()
            if isinstance(outcome, BaseException):
                st.status = StageStatus.FAILED
                st.error = str(outcome)
                unavailable.append(provider.name)
            else:
                st.status = StageStatus.DONE
                st.summary = _summarise(outcome)
                collected.extend(outcome)
                if any(s.data.get("authoritative_clean") is True for s in outcome):
                    had_authoritative = True
            _notify(on_stage, st)

        return collected, had_authoritative

    def _skip_named(
        self,
        name: str,
        availability: Availability,
        detail: str,
        stages: list[StageResult],
        unavailable: list[str],
        on_stage: OnStage | None,
        *,
        title_key: str = "stage.reputation",
    ) -> None:
        """Record a SKIPPED stage for an unavailable provider (NO_KEY, OFFLINE)."""
        now = datetime.now(UTC)
        st = StageResult(
            stage_id=name,
            title_key=title_key,
            status=StageStatus.SKIPPED,
            availability=availability,
            summary=detail,
            started_at=now,
            finished_at=now,
        )
        stages.append(st)
        unavailable.append(name)
        _notify(on_stage, st)

    # ------------------------------------------------------------------ #
    # URL pipeline (§7)
    # ------------------------------------------------------------------ #
    async def _run_url(
        self,
        request: ScanRequest,
        *,
        on_stage: OnStage | None,
        cancel: asyncio.Event,
    ) -> ScanReport:
        """Execute the URL pipeline of §7 and return a report."""
        assert request.url is not None
        started = datetime.now(UTC)
        scan_id = uuid.uuid4().hex
        self._paths.ensure()

        stages: list[StageResult] = []
        signals: list[Signal] = []
        unavailable: list[str] = []
        file_info_dl: FileInfo | None = None
        net = request.allow_network and self._config.allow_network

        # Stage 1: normalize
        with self._stage("url_normalize", "stage.url_normalize", stages, on_stage) as st:
            nurl = url_normalize.normalize(request.url)
            st.summary = nurl.host
        url_info = UrlInfo(
            original=nurl.original,
            normalized=nurl.normalized,
            registrable_domain=nurl.registrable_domain,
            is_idn=nurl.is_idn,
            punycode_host=nurl.punycode_host,
        )

        # Stage 2: heuristics (local, instant)
        with self._stage("url_heuristics", "stage.url_heuristics", stages, on_stage) as st:
            heur = url_heuristics.evaluate(nurl)
            signals += heur
            st.summary = f"{len(heur)} signal(s)"

        had_authoritative = False
        if net and not cancel.is_set():
            # Stage 3: URL reputation providers
            rep, rep_auth = await self._run_url_providers(
                request.url, stages, unavailable, on_stage
            )
            signals += rep
            had_authoritative = had_authoritative or rep_auth

            # Stage 4: domain age (RDAP)
            with self._stage("domain_age", "stage.domain_age", stages, on_stage) as st:
                age = await domain_age_days(nurl.registrable_domain or nurl.host)
                url_info.domain_age_days = age
                if age is not None and age < 30:
                    signals.append(
                        self._url_signal(
                            Severity.HIGH,
                            25,
                            "signal.url.young_domain",
                            f"Domain registered {age} days ago",
                        )
                    )
                st.summary = "unknown" if age is None else f"{age} days"

            # Stage 5: TLS
            with self._stage("tls", "stage.tls", stages, on_stage) as st:
                tls = await inspect_tls(nurl.host)
                url_info.tls_valid = tls.valid
                url_info.tls_issuer = tls.issuer
                if tls.valid is False or tls.host_match is False:
                    signals.append(
                        self._url_signal(
                            Severity.MEDIUM,
                            20,
                            "signal.url.tls_invalid",
                            "TLS certificate invalid or host mismatch",
                        )
                    )
                st.summary = "valid" if tls.valid else "invalid/unknown"

            # Stage 6-7: redirects + HEAD metadata
            with self._stage("redirects", "stage.redirects", stages, on_stage) as st:
                info = await inspect_url(request.url, follow_redirects=request.follow_redirects)
                url_info.final_url = info.final_url
                url_info.redirect_chain = info.redirect_chain
                url_info.http_status = info.http_status
                url_info.content_type = info.content_type
                url_info.content_length = info.content_length
                url_info.content_disposition_filename = info.content_disposition_filename
                if info.registrable_changed:
                    signals.append(
                        self._url_signal(
                            Severity.MEDIUM,
                            15,
                            "signal.url.redirect_domain_change",
                            "Redirect chain changes the registrable domain",
                        )
                    )
                st.summary = f"{len(info.redirect_chain)} redirect(s)"

            # Stage 8: download + full file analysis (§6), only on explicit consent
            if request.allow_download and not cancel.is_set():
                file_info_dl, file_signals, dl_auth = await self._download_and_scan(
                    request, stages, unavailable, on_stage, cancel
                )
                signals += file_signals
                had_authoritative = had_authoritative or dl_auth
        else:
            self._skip_named(
                "url_reputation",
                Availability.OFFLINE,
                "network disabled",
                stages,
                unavailable,
                on_stage,
                title_key="stage.url_reputation",
            )

        verdict, risk, reason_key, reason_en = self._score(
            signals,
            had_authoritative=had_authoritative,
            cancelled=cancel.is_set(),
            target_noun="URL",
        )
        finished = datetime.now(UTC)
        return ScanReport(
            scan_id=scan_id,
            app_version=_app_version(),
            request=request,
            started_at=started,
            finished_at=finished,
            duration_s=(finished - started).total_seconds(),
            file=file_info_dl,
            url=url_info,
            signals=signals,
            stages=stages,
            verdict=verdict,
            risk_score=risk,
            verdict_reason_key=reason_key,
            verdict_reason_en=reason_en,
            incomplete=bool(unavailable) or cancel.is_set(),
            unavailable_sources=unavailable,
        )

    async def _download_and_scan(
        self,
        request: ScanRequest,
        stages: list[StageResult],
        unavailable: list[str],
        on_stage: OnStage | None,
        cancel: asyncio.Event,
    ) -> tuple[FileInfo | None, list[Signal], bool]:
        """Stage 8: safely download the URL body and run the file pipeline over it."""
        assert request.url is not None
        signals: list[Signal] = []
        with self._stage("download", "stage.download", stages, on_stage) as st:
            try:
                downloaded = await safe_download(
                    request.url,
                    self._paths.tmp_dir,
                    max_bytes=request.max_download_bytes,
                    timeout_s=request.timeout_s,
                    cancel=cancel,
                )
            except Exception as exc:  # noqa: BLE001 - network/IO; report, don't crash
                st.status = StageStatus.FAILED
                st.error = str(exc)
                unavailable.append("download")
                return None, signals, False
            st.summary = "download.bin"

        workdir = downloaded.parent
        try:
            file_info = await self._collect_file_info(downloaded, stages, on_stage)
            signals += self._identify_signals(file_info)
            signals += signature_signals(file_info.signature) if file_info.signature else []
            engine_signals, had_auth = await self._run_engines(
                file_info, workdir, request, stages, unavailable, on_stage, cancel
            )
            signals += engine_signals
            return file_info, signals, had_auth
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    async def _run_url_providers(
        self,
        url: str,
        stages: list[StageResult],
        unavailable: list[str],
        on_stage: OnStage | None,
    ) -> tuple[list[Signal], bool]:
        """Query URL-reputation providers concurrently (§7 stage 3)."""
        providers = build_url_providers(self._limiter, allow_network=True)
        runnable: list[Provider] = []
        for provider in providers:
            availability, detail = await provider.availability()
            if availability is Availability.READY:
                runnable.append(provider)
            else:
                self._skip_named(
                    provider.name,
                    availability,
                    detail,
                    stages,
                    unavailable,
                    on_stage,
                    title_key="stage.url_reputation",
                )

        stage_by_name: dict[str, StageResult] = {}
        for provider in runnable:
            st = StageResult(
                stage_id=provider.name,
                title_key="stage.url_reputation",
                status=StageStatus.RUNNING,
                started_at=datetime.now(UTC),
            )
            stages.append(st)
            stage_by_name[provider.name] = st
            _notify(on_stage, st)

        results = await asyncio.gather(
            *(p.lookup_url(url) for p in runnable), return_exceptions=True
        )
        collected: list[Signal] = []
        had_authoritative = False
        for provider, outcome in zip(runnable, results, strict=True):
            st = stage_by_name[provider.name]
            st.finished_at = datetime.now(UTC)
            if isinstance(outcome, BaseException):
                st.status = StageStatus.FAILED
                st.error = str(outcome)
                unavailable.append(provider.name)
            else:
                st.status = StageStatus.DONE
                st.summary = _summarise(outcome)
                collected.extend(outcome)
                had_authoritative = True  # a reputation source answered
            _notify(on_stage, st)
        return collected, had_authoritative

    def _url_signal(self, severity: Severity, weight_value: int, key: str, title: str) -> Signal:
        return Signal(
            source="url",
            kind=SourceKind.HEURISTIC,
            severity=severity,
            title_key=key,
            title_en=title,
            weight=weight_value,
        )

    # ------------------------------------------------------------------ #
    # Scoring
    # ------------------------------------------------------------------ #
    def _score(
        self,
        signals: list[Signal],
        *,
        had_authoritative: bool,
        cancelled: bool,
        target_noun: str = "file",
    ) -> tuple[Verdict, int, str, str]:
        """Run the scoring stage; a cancelled scan is always UNKNOWN."""
        if cancelled:
            return (
                Verdict.UNKNOWN,
                0,
                "verdict.cancelled",
                f"{target_noun.capitalize()} scan cancelled by the user",
            )
        return score(signals, had_authoritative_source=had_authoritative, target_noun=target_noun)

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
