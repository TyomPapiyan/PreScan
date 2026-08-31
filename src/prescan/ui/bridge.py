"""QObject bridge between QML and the engine core.

All calls into ``core`` run on the qasync event loop so the Qt UI never blocks
(§9.9): the pipeline is scheduled with ``asyncio``; its per-stage callback and
the final result update the QML models directly (same loop thread). This module
is Qt-only glue — no detection logic lives here (§10.1 keeps that in core).
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import datetime
from pathlib import Path
from typing import Any

from PySide6.QtCore import Property, QObject, Signal, Slot

from prescan.core.config import AppConfig, Paths
from prescan.core.models import (
    Availability,
    ScanReport,
    ScanRequest,
    StageResult,
    TargetKind,
    Verdict,
)
from prescan.core.pipeline import Pipeline
from prescan.core.ratelimit import RateLimiter
from prescan.core.storage import Storage
from prescan.ui.models_qml import DictListModel

_VERDICT_COLOR = {
    Verdict.SAFE: "#2ECC71",
    Verdict.SUSPICIOUS: "#F5A623",
    Verdict.DANGEROUS: "#E5484D",
    Verdict.UNKNOWN: "#6E6E78",
}

#: URL-scan sources that receive the FULL URL, vs Safe Browsing (hash-prefix).
FULL_URL_SOURCES = ("VirusTotal (URL lookup)", "urlscan.io", "URLhaus")


class Bridge(QObject):
    """The single QML-facing object wiring buttons to the engine."""

    busyChanged = Signal()
    resultChanged = Signal()
    scanStarted = Signal()
    scanFinished = Signal()
    themeChanged = Signal()
    languageChanged = Signal()
    settingsChanged = Signal()
    showResult = Signal()
    keyCheckResult = Signal(str, str)  # provider id, human-readable result

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._config = AppConfig.load()
        self._paths = Paths.resolve()
        self._paths.ensure()
        self._storage = Storage(self._paths.db_path)
        self._pipeline = Pipeline(self._config, self._storage)
        self._limiter = RateLimiter()

        self._stagesModel = DictListModel(["stageId", "title", "status", "availability", "summary"])
        self._signalsModel = DictListModel(
            ["source", "severity", "title", "detail", "weight", "mitre"]
        )
        self._historyModel = DictListModel(["stamp", "verdict", "target", "sha256"])
        self._quarantineModel = DictListModel(["entryId", "name", "verdict"])
        self._enginesModel = DictListModel(["name", "availability", "detail"])

        self._busy = False
        self._tasks: set[asyncio.Task[Any]] = set()
        self._cancel = asyncio.Event()
        self._report: ScanReport | None = None
        self._theme = self._config.theme
        self._language = self._config.language
        self._verdict = ""
        self._risk = 0
        self._reason = ""
        self._target = ""
        self._incomplete = False

    # ---- models (exposed to QML as constant properties) --------------- #
    @Property(QObject, constant=True)
    def stagesModel(self) -> QObject:
        return self._stagesModel

    @Property(QObject, constant=True)
    def signalsModel(self) -> QObject:
        return self._signalsModel

    @Property(QObject, constant=True)
    def historyModel(self) -> QObject:
        return self._historyModel

    @Property(QObject, constant=True)
    def quarantineModel(self) -> QObject:
        return self._quarantineModel

    @Property(QObject, constant=True)
    def enginesModel(self) -> QObject:
        return self._enginesModel

    # ---- properties ---------------------------------------------------- #
    @Property(bool, notify=busyChanged)
    def busy(self) -> bool:
        return self._busy

    @Property(str, notify=resultChanged)
    def verdict(self) -> str:
        return self._verdict

    @Property(int, notify=resultChanged)
    def riskScore(self) -> int:
        return self._risk

    @Property(str, notify=resultChanged)
    def gauge(self) -> str:
        if not self._verdict or self._verdict == Verdict.UNKNOWN.value:
            return "—"
        return str(self._risk)

    @Property(str, notify=resultChanged)
    def reasonText(self) -> str:
        return self._reason

    @Property(str, notify=resultChanged)
    def verdictColor(self) -> str:
        try:
            return _VERDICT_COLOR[Verdict(self._verdict)]
        except ValueError:
            return _VERDICT_COLOR[Verdict.UNKNOWN]

    @Property(str, notify=resultChanged)
    def target(self) -> str:
        return self._target

    @Property(bool, notify=resultChanged)
    def incomplete(self) -> bool:
        return self._incomplete

    @Property(str, notify=themeChanged)
    def theme(self) -> str:
        return self._theme

    @Property(str, notify=languageChanged)
    def language(self) -> str:
        return self._language

    # ---- scanning ------------------------------------------------------ #
    @Slot(str)
    def scanFile(self, path: str) -> None:
        local = path
        if local.startswith("file://"):
            local = local[len("file://") :]
        request = ScanRequest(target_kind=TargetKind.FILE, file_path=Path(local))
        self._start(request)

    @Slot(str, bool, bool)
    def scanUrl(self, url: str, download: bool, follow_redirects: bool) -> None:
        request = ScanRequest(
            target_kind=TargetKind.URL,
            url=url,
            allow_download=download,
            follow_redirects=follow_redirects,
        )
        self._start(request)

    def _start(self, request: ScanRequest) -> None:
        if self._busy:
            return
        self._cancel = asyncio.Event()
        self._stagesModel.clear()
        self._signalsModel.clear()
        self._set_busy(True)
        self.scanStarted.emit()
        self._schedule(self._run(request))

    async def _run(self, request: ScanRequest) -> None:
        try:
            report = await self._pipeline.run(request, on_stage=self._on_stage, cancel=self._cancel)
        except Exception as exc:  # noqa: BLE001 - surface, never crash the UI
            self._verdict, self._risk = Verdict.UNKNOWN.value, 0
            self._reason = f"Scan failed: {exc}"
            self.resultChanged.emit()
        else:
            self._apply_report(report)
        finally:
            self._set_busy(False)
            self.scanFinished.emit()

    def _on_stage(self, stage: StageResult) -> None:
        self._stagesModel.upsert(
            "stageId",
            {
                "stageId": stage.stage_id,
                "title": stage.title_key,
                "status": stage.status.value,
                "availability": stage.availability.value,
                "summary": stage.summary,
            },
        )

    def _apply_report(self, report: ScanReport) -> None:
        self._report = report
        self._verdict = report.verdict.value
        self._risk = report.risk_score
        self._reason = report.verdict_reason_en
        self._incomplete = report.incomplete
        if report.file is not None:
            self._target = f"{report.file.name} · {report.file.detected_type}"
        elif report.url is not None:
            self._target = report.url.normalized
        self._signalsModel.replace(
            [
                {
                    "source": s.source,
                    "severity": s.severity.value,
                    "title": self._signal_title(s),
                    "detail": s.detail,
                    "weight": s.weight,
                    "mitre": ", ".join(s.mitre),
                }
                for s in report.signals
            ]
        )
        self.resultChanged.emit()

    def _signal_title(self, s: Any) -> str:
        """Localised, human-readable signal title for the result screen.

        The ML signal is the one DoD requires visible and translated (e.g.
        "ML-модель: 87% вероятность вредоносности"); its percentage is read from
        the signal payload so the text is built in the active UI language.
        """
        if s.source == "ml":
            probability = s.data.get("probability")
            if probability is not None:
                pct = round(float(probability) * 100)
                return self.tr("ML model: %1% likely malicious").replace("%1", str(pct))
            return self.tr("ML model could not score the file")
        return str(s.title_en)
        self.loadHistory()

    @Slot()
    def cancel(self) -> None:
        self._cancel.set()

    def _set_busy(self, value: bool) -> None:
        if self._busy != value:
            self._busy = value
            self.busyChanged.emit()

    # ---- engines / history / quarantine ------------------------------- #
    @Slot()
    def refreshEngines(self) -> None:
        self._schedule(self._refresh_engines())

    def _schedule(self, coro: Any) -> None:
        """Schedule a coroutine on the running loop; no-op cleanly if none yet.

        QML ``Component.onCompleted`` can fire before the qasync loop is running
        (and in tests before any loop is set); guard so we never raise or leave a
        coroutine un-awaited.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            coro.close()  # no running loop yet; caller re-invokes when it starts
            return
        task = loop.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def current_language(self) -> str:
        """Plain (non-Qt) accessor for the language code, for the app wiring."""
        return self._language

    async def _refresh_engines(self) -> None:
        from prescan.core.engines import build_engines

        rows = []
        for engine in build_engines(self._config, self._paths):
            availability, detail = await engine.availability()
            rows.append({"name": engine.name, "availability": availability.value, "detail": detail})
        self._enginesModel.replace(rows)

    @Slot()
    def loadHistory(self) -> None:
        rows = [
            {
                "stamp": entry.created_at.strftime("%Y-%m-%d %H:%M"),
                "verdict": entry.verdict,
                "target": entry.target,
                "sha256": entry.sha256,
            }
            for entry in self._storage.list_history(limit=200)
        ]
        self._historyModel.replace(rows)

    @Slot(str, str)
    def filterHistory(self, verdict: str, query: str) -> None:
        """Reload history filtered by verdict ('all' = any) and a name/hash query."""
        q = query.strip().lower()
        rows = []
        for entry in self._storage.list_history(limit=500):
            if verdict not in ("all", "") and entry.verdict != verdict:
                continue
            if q and q not in entry.target.lower() and q not in entry.sha256.lower():
                continue
            rows.append(
                {
                    "stamp": entry.created_at.strftime("%Y-%m-%d %H:%M"),
                    "verdict": entry.verdict,
                    "target": entry.target,
                    "sha256": entry.sha256,
                }
            )
        self._historyModel.replace(rows)

    @Slot()
    def clearHistory(self) -> None:
        self._storage.clear_history()
        self._historyModel.clear()

    @Slot(str, result=bool)
    def openReport(self, sha256: str) -> bool:
        """Load a stored report by hash and show it on the result screen."""
        if not sha256:
            return False
        report = self._storage.get_report(sha256)
        if report is None:
            return False
        self._apply_report(report)
        self.showResult.emit()
        return True

    @Slot()
    def loadQuarantine(self) -> None:
        from prescan.core.quarantine import list_entries

        rows = [
            {"entryId": e.entry_id, "name": e.original_name, "verdict": e.verdict}
            for e in list_entries()
        ]
        self._quarantineModel.replace(rows)

    @Slot()
    def quarantineCurrent(self) -> None:
        if self._report is None or self._report.file is None:
            return
        from prescan.core.quarantine import quarantine

        quarantine(self._report.file.path, self._report)
        self.loadQuarantine()

    @Slot(str, str, result=bool)
    def restoreQuarantine(self, entry_id: str, dest: str) -> bool:
        """Restore a quarantined file to a chosen directory (with UI confirmation)."""
        from prescan.core.quarantine import QuarantineError, restore

        out = dest[len("file://") :] if dest.startswith("file://") else dest
        try:
            restore(entry_id, Path(out))
        except QuarantineError:
            return False
        return True

    @Slot(str)
    def deleteQuarantine(self, entry_id: str) -> None:
        from prescan.core.quarantine import purge

        purge(entry_id)
        self.loadQuarantine()

    @Slot(str)
    def rescanQuarantine(self, entry_id: str) -> None:
        """Restore the quarantined file to a temp dir and scan it again."""
        import tempfile

        from prescan.core.quarantine import QuarantineError, restore

        try:
            tmp = Path(tempfile.mkdtemp(prefix="prescan-rescan-", dir=self._paths.tmp_dir))
            restored = restore(entry_id, tmp)
        except QuarantineError:
            return
        self.scanFile(str(restored))

    @Slot(str, result=bool)
    def saveReport(self, path: str) -> bool:
        if self._report is None:
            return False
        from prescan.core.report import to_html

        out = path[len("file://") :] if path.startswith("file://") else path
        Path(out).write_text(to_html(self._report, lang=self._language), encoding="utf-8")
        return True

    # ---- settings / privacy ------------------------------------------- #
    def _persist(self) -> None:
        with contextlib.suppress(OSError):
            self._config.save()

    @Slot(str)
    def setTheme(self, name: str) -> None:
        self._theme = name
        self._config.theme = name
        self._persist()
        self.themeChanged.emit()

    @Slot(str)
    def setLanguage(self, code: str) -> None:
        self._language = code
        self._config.language = code
        self._persist()
        self.languageChanged.emit()

    # ---- privacy toggles (bound to AppConfig, persisted) -------------- #
    @Property(bool, notify=settingsChanged)
    def neverUpload(self) -> bool:
        return self._config.never_upload_files

    @Property(bool, notify=settingsChanged)
    def onlyHashes(self) -> bool:
        return self._config.only_send_hashes

    @Property(bool, notify=settingsChanged)
    def allowNetwork(self) -> bool:
        return self._config.allow_network

    @Slot(bool)
    def setNeverUpload(self, value: bool) -> None:
        self._config.never_upload_files = value
        self._persist()
        self.settingsChanged.emit()

    @Slot(bool)
    def setOnlyHashes(self, value: bool) -> None:
        self._config.only_send_hashes = value
        self._persist()
        self.settingsChanged.emit()

    @Slot(bool)
    def setAllowNetwork(self, value: bool) -> None:
        self._config.allow_network = value
        self._persist()
        self.settingsChanged.emit()

    # ---- scanning limits (bound to AppConfig, persisted) -------------- #
    @Property(int, notify=settingsChanged)
    def maxDownloadMb(self) -> int:
        return self._config.max_download_bytes // (1024 * 1024)

    @Property(int, notify=settingsChanged)
    def scanTimeoutS(self) -> int:
        return int(self._config.scan_timeout_s)

    @Property(int, notify=settingsChanged)
    def archiveDepth(self) -> int:
        return self._config.max_archive_depth

    @Property(int, notify=settingsChanged)
    def cacheTtlDays(self) -> int:
        return self._config.cache_ttl_days

    @Slot(int)
    def setMaxDownloadMb(self, value: int) -> None:
        self._config.max_download_bytes = max(1, value) * 1024 * 1024
        self._persist()
        self.settingsChanged.emit()

    @Slot(int)
    def setScanTimeoutS(self, value: int) -> None:
        self._config.scan_timeout_s = float(max(1, value))
        self._persist()
        self.settingsChanged.emit()

    @Slot(int)
    def setArchiveDepth(self, value: int) -> None:
        self._config.max_archive_depth = max(1, value)
        self._persist()
        self.settingsChanged.emit()

    @Slot(int)
    def setCacheTtlDays(self, value: int) -> None:
        self._config.cache_ttl_days = max(0, value)
        self._persist()
        self.settingsChanged.emit()

    # ---- API keys (kept in the OS keyring, never shown) --------------- #
    @Slot(str, result=bool)
    def hasApiKey(self, provider: str) -> bool:
        from prescan.core.config import get_api_key

        return bool(get_api_key(provider))

    @Slot(str, str)
    def setApiKey(self, provider: str, key: str) -> None:
        from prescan.core.config import set_api_key

        if key:
            set_api_key(provider, key)
            self.settingsChanged.emit()

    @Slot(str)
    def checkKey(self, provider: str) -> None:
        """Probe a provider with its stored key; emit keyCheckResult(provider, text)."""
        self._schedule(self._check_key(provider))

    async def _check_key(self, provider: str) -> None:
        from prescan.core.config import get_api_key
        from prescan.core.providers import build_hash_providers, build_url_providers

        by_name = {
            p.name: p
            for p in [
                *build_hash_providers(self._limiter),
                *build_url_providers(self._limiter),
            ]
        }
        prov = by_name.get(provider)
        if prov is None or not get_api_key(provider):
            self.keyCheckResult.emit(provider, "No key configured")
            return
        try:
            availability, detail = await prov.availability()
            if availability.value != "ready":
                self.keyCheckResult.emit(
                    provider, self.availabilityText(availability.value, detail)
                )
                return
            quota = await prov.remaining_quota()
            self.keyCheckResult.emit(provider, f"OK · quota: {quota}" if quota else "OK")
        except Exception as exc:  # noqa: BLE001 - report any probe failure to the UI
            self.keyCheckResult.emit(provider, f"Error: {exc}")

    @Slot(result="QStringList")
    def providerIds(self) -> list[str]:
        from prescan.core.config import PROVIDER_IDS

        return list(PROVIDER_IDS)

    @Slot(str, str, result=str)
    def availabilityText(self, availability: str, detail: str) -> str:
        """Map an Availability value to user guidance (not one generic string)."""
        mapping = {
            Availability.READY.value: "Ready",
            Availability.NO_KEY.value: "Add an API key in Settings",
            Availability.NO_RULES.value: "Rules not downloaded — update rules",
            Availability.NO_MODEL.value: "ML model not installed",
            Availability.NOT_INSTALLED.value: "Not installed",
            Availability.OFFLINE.value: "Source temporarily unavailable (offline)",
            Availability.ERROR.value: "Source temporarily unavailable",
            Availability.UNSUPPORTED_OS.value: "Not available on this OS",
            Availability.DISABLED.value: "Disabled",
        }
        return mapping.get(availability, detail or availability)

    @Slot(result="QStringList")
    def fullUrlSources(self) -> list[str]:
        """Sources that receive the full URL on a link scan (§6.2 disclosure)."""
        return list(FULL_URL_SOURCES)

    @Slot(result=str)
    def privacyNote(self) -> str:
        return (
            "When you scan a link, the full URL is sent to: "
            + ", ".join(FULL_URL_SOURCES)
            + ". Only truncated hash prefixes are sent to Google Safe Browsing — "
            "never the full URL."
        )

    def _now(self) -> str:  # pragma: no cover - trivial
        return datetime.now().astimezone().strftime("%H:%M:%S")
