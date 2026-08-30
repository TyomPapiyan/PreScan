"""Scoring: turn a list of signals into a verdict and a 0-100 risk score.

Pure function, no I/O beyond loading the editable weight table once (§8). There
is no meta-model: only explicit rules plus a weighted sum for the visible gauge.

Rule layers:
  §8.1 hard DANGEROUS rules  -> any ``decisive`` signal wins, floor 80.
  §8.2 SUSPICIOUS rules      -> any signal with data["escalates"], or ML >= 0.70,
                                clamped 40-79.
  §8.3 SAFE / UNKNOWN        -> SAFE only with an authoritative clean source,
                                otherwise UNKNOWN (honest over a green tick).
  §8.6 false-positive guard  -> a valid trusted signature blocks packing-only
                                escalation and pulls the score down.
"""

from __future__ import annotations

import tomllib
from functools import lru_cache
from importlib import resources
from typing import Final

import structlog

from prescan.core.models import Severity, Signal, Verdict

log = structlog.get_logger(__name__)

_DANGEROUS_FLOOR: Final = 80
_SUSPICIOUS_MIN: Final = 40
_SUSPICIOUS_MAX: Final = 79
_SAFE_CEIL: Final = 20

_SEVERITY_ORDER: Final = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@lru_cache(maxsize=1)
def load_weights() -> dict[str, dict[str, int]]:
    """Load and cache the signal weight table from resources (§8.4)."""
    try:
        text = (
            resources.files("prescan.resources")
            .joinpath("scoring_weights.toml")
            .read_text(encoding="utf-8")
        )
        data = tomllib.loads(text)
    except (OSError, tomllib.TOMLDecodeError) as exc:  # pragma: no cover - packaging
        log.warning("weights.load_failed", error=str(exc))
        return {}
    return {section: dict(values) for section, values in data.items()}


def weight(category: str, key: str, default: int = 0) -> int:
    """Return a single weight value from the table, or ``default``."""
    return load_weights().get(category, {}).get(key, default)


def _max_severity(signals: list[Signal]) -> int:
    """Return the numeric rank of the most severe signal (0 if none)."""
    return max((_SEVERITY_ORDER[s.severity] for s in signals), default=0)


def _has_valid_trusted_signature(signals: list[Signal]) -> bool:
    """True if a signal reports a valid, trusted code signature."""
    return any(s.data.get("valid_trusted_signature") is True for s in signals)


def score(
    signals: list[Signal],
    *,
    had_authoritative_source: bool,
    target_noun: str = "file",
) -> tuple[Verdict, int, str, str]:
    """Return (verdict, risk_score, reason_key, reason_en). Pure function, no I/O.

    ``target_noun`` ("file" or "URL") is interpolated into the human reason so
    URL scans read naturally; the reason_key stays target-neutral for i18n (M5).
    """
    raw = sum(s.weight for s in signals)
    base_score = max(0, min(100, raw))

    # ---- §8.1 hard DANGEROUS rules -------------------------------------- #
    decisive = [s for s in signals if s.decisive]
    if decisive:
        top = max(decisive, key=lambda s: _SEVERITY_ORDER[s.severity])
        risk = max(_DANGEROUS_FLOOR, base_score)
        return (
            Verdict.DANGEROUS,
            risk,
            "verdict.dangerous",
            f"Decisive detection: {top.title_en}",
        )

    # ---- §8.6 false-positive guard -------------------------------------- #
    trusted = _has_valid_trusted_signature(signals)
    ml_prob = _ml_probability(signals)

    # ---- §8.2 SUSPICIOUS rules ------------------------------------------ #
    # A signal escalates only if it declares data["escalates"] (a §8.2 row set by
    # its producer). A packing-only (entropy) escalation is suppressed by a valid
    # trusted signature (§8.6). ML >= 0.70 escalates but never on its own reaches
    # DANGEROUS (§8.6): it is only ever a SUSPICIOUS trigger here.
    escalating = [
        s
        for s in signals
        if s.data.get("escalates") is True and not (trusted and s.data.get("packing_only") is True)
    ]
    ml_escalates = ml_prob is not None and ml_prob >= 0.70
    if escalating or ml_escalates:
        risk = max(_SUSPICIOUS_MIN, min(_SUSPICIOUS_MAX, base_score))
        reason = escalating[0].title_en if escalating else "ML flagged this as likely malicious"
        if escalating:
            top = max(escalating, key=lambda s: _SEVERITY_ORDER[s.severity])
            reason = top.title_en
        return (
            Verdict.SUSPICIOUS,
            risk,
            "verdict.suspicious",
            f"Attention required: {reason}",
        )

    # ---- §8.3 SAFE / UNKNOWN -------------------------------------------- #
    ml_ok = (ml_prob is not None and ml_prob < 0.20) or (ml_prob is None and trusted)
    no_low_or_worse = _max_severity(signals) < _SEVERITY_ORDER[Severity.LOW]

    if had_authoritative_source and no_low_or_worse and ml_ok:
        risk = min(_SAFE_CEIL, base_score)
        return (
            Verdict.SAFE,
            risk,
            "verdict.safe",
            f"No authoritative source flagged this {target_noun}",
        )

    # UNKNOWN: numeric gauge is hidden in the UI; keep a real number in the report.
    risk = max(0, min(_SUSPICIOUS_MIN - 1, base_score))
    return (
        Verdict.UNKNOWN,
        risk,
        "verdict.unknown",
        f"Not enough authoritative signal to clear or condemn this {target_noun}",
    )


def _ml_probability(signals: list[Signal]) -> float | None:
    """Return the ML malicious probability if the ML engine produced one."""
    for s in signals:
        if s.source == "ml" and "probability" in s.data:
            try:
                return float(s.data["probability"])
            except (TypeError, ValueError):
                return None
    return None
