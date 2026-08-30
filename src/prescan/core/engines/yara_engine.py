"""YARA-X rule matching engine.

Rules come from YARA Forge downloaded into the user data dir (§2.3); they are
never committed. With no rules the engine reports ``NO_RULES`` and is skipped.
Rule metadata (``severity``/``score``) drives the scoring layer (§8.1/§8.2).

Compilation and scanning are CPU-bound and run in a worker thread so the event
loop stays responsive (§9.9). Malformed rules or input never crash the pipeline
(§10.4): failures degrade to skip or an INFO signal.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

import structlog

from prescan.core.engines.base import ScanContext
from prescan.core.models import Availability, Severity, Signal, SourceKind
from prescan.core.scoring import weight

if TYPE_CHECKING:
    import yara_x

log = structlog.get_logger(__name__)

_RULE_GLOBS = ("*.yar", "*.yara")


class YaraEngine:
    """Signature matching backed by yara-x."""

    name: ClassVar[str] = "yara-x"
    kind: ClassVar[SourceKind] = SourceKind.LOCAL_ENGINE
    stage_id: ClassVar[str] = "yara"

    def __init__(self, rules_dir: Path) -> None:
        self._rules_dir = rules_dir
        self._rules: yara_x.Rules | None = None
        self._rule_count = 0

    def _rule_files(self) -> list[Path]:
        """Return every rule file present in the rules directory."""
        files: list[Path] = []
        for pattern in _RULE_GLOBS:
            files.extend(sorted(self._rules_dir.glob(pattern)))
        return files

    async def availability(self) -> tuple[Availability, str]:
        """Report NO_RULES until YARA Forge has been downloaded."""
        if not self._rule_files():
            return Availability.NO_RULES, "YARA rules not downloaded"
        return Availability.READY, "rules available"

    def _compile(self) -> yara_x.Rules:
        """Compile all rule files once and cache the result. Runs in a thread."""
        import yara_x

        compiler = yara_x.Compiler()
        compiler.ignore_invalid_rules(True)
        for path in self._rule_files():
            try:
                compiler.add_source(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, yara_x.CompileError) as exc:
                log.warning("yara.compile_skip", file=str(path), error=str(exc))
        rules = compiler.build()
        self._rule_count = sum(1 for _ in rules)
        return rules

    async def scan(self, ctx: ScanContext) -> list[Signal]:
        """Match the file against the compiled rules. Never raises (§10.4)."""
        try:
            if self._rules is None:
                self._rules = await asyncio.to_thread(self._compile)
            matches = await asyncio.to_thread(self._scan_sync, self._rules, ctx)
        except Exception as exc:  # noqa: BLE001 - untrusted rules/input (§10.4)
            log.warning("yara.scan_failed", error=str(exc))
            return [
                Signal(
                    source=self.name,
                    kind=self.kind,
                    severity=Severity.INFO,
                    title_key="signal.yara.error",
                    title_en="YARA scan could not complete",
                    detail=str(exc),
                )
            ]
        return matches

    def _scan_sync(self, rules: yara_x.Rules, ctx: ScanContext) -> list[Signal]:
        """Synchronous scan body executed in a worker thread."""
        import yara_x

        scanner = yara_x.Scanner(rules)
        scanner.set_timeout(int(max(1, ctx.timeout_s)))
        results = scanner.scan_file(str(ctx.path))
        return [self._to_signal(rule) for rule in results.matching_rules]

    def _to_signal(self, rule: yara_x.Rule) -> Signal:
        """Map a matched rule and its metadata to a scored Signal (§8.1/§8.2)."""
        meta = dict(rule.metadata)
        severity_meta = str(meta.get("severity", "")).lower()
        score_meta = _as_int(meta.get("score"))

        if severity_meta in {"critical", "high"} or (score_meta is not None and score_meta >= 75):
            level = Severity.CRITICAL if severity_meta == "critical" else Severity.HIGH
            key = "yara_critical" if level is Severity.CRITICAL else "yara_high"
            return self._signal(rule, level, weight("local_engine", key), decisive=True, meta=meta)
        if severity_meta == "medium" or (score_meta is not None and 40 <= score_meta <= 74):
            return self._signal(
                rule,
                Severity.MEDIUM,
                weight("local_engine", "yara_medium"),
                escalates=True,
                meta=meta,
            )
        return self._signal(rule, Severity.LOW, weight("local_engine", "yara_low"), meta=meta)

    def _signal(
        self,
        rule: yara_x.Rule,
        severity: Severity,
        rule_weight: int,
        *,
        decisive: bool = False,
        escalates: bool = False,
        meta: dict[str, Any],
    ) -> Signal:
        return Signal(
            source=self.name,
            kind=self.kind,
            severity=severity,
            title_key="signal.yara.match",
            title_en=f"YARA rule matched: {rule.identifier}",
            detail=rule.identifier,
            weight=rule_weight,
            decisive=decisive,
            data={
                "rule": rule.identifier,
                "namespace": rule.namespace,
                "meta": meta,
                "escalates": escalates,
            },
        )


def _as_int(value: object) -> int | None:
    """Best-effort int conversion for rule metadata."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None
