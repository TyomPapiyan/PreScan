"""QObject bridge between QML and the engine core.

All calls into ``core`` run on the qasync event loop so the Qt UI never blocks
(§9.9): the pipeline is scheduled with ``asyncio``; its per-stage callback and
the final result update the QML models directly (same loop thread). This module
is Qt-only glue — no detection logic lives here (§10.1 keeps that in core).
"""

from __future__ import annotations

import asyncio
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

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._config = AppConfig.load()
        self._paths = Paths.resolve()
        self._paths.ensure()
        self._storage = Storage(self._paths.db_path)
        self._pipeline = Pipeline(self._config, self._storage)

        self._stagesModel = DictListModel(["stageId", "title", "status", "availability", "summary"])
        self._signalsModel = DictListModel(
            ["source", "severity", "title", "detail", "weight", "mitre"]
        )
        self._historyModel = DictListModel(["stamp", "verdict", "target"])
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
                    "title": s.title_en,
                    "detail": s.detail,
                    "weight": s.weight,
                    "mitre": ", ".join(s.mitre),
                }
                for s in report.signals
            ]
        )
        self.resultChanged.emit()
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
            }
            for entry in self._storage.list_history(limit=100)
        ]
        self._historyModel.replace(rows)

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

    @Slot(str, result=bool)
    def saveReport(self, path: str) -> bool:
        if self._report is None:
            return False
        from prescan.core.report import to_html

        out = path[len("file://") :] if path.startswith("file://") else path
        Path(out).write_text(to_html(self._report, lang=self._language), encoding="utf-8")
        return True

    # ---- settings / privacy ------------------------------------------- #
    @Slot(str)
    def setTheme(self, name: str) -> None:
        self._theme = name
        self.themeChanged.emit()

    @Slot(str)
    def setLanguage(self, code: str) -> None:
        self._language = code
        self.languageChanged.emit()

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
