"""Tests for core/scoring.py (M1 baseline; full per-rule table lands on M4)."""

from __future__ import annotations

from prescan.core.models import Severity, Signal, SourceKind, Verdict
from prescan.core.scoring import score


def _sig(
    severity: Severity,
    *,
    weight: int = 0,
    decisive: bool = False,
    source: str = "test",
    data: dict[str, object] | None = None,
) -> Signal:
    return Signal(
        source=source,
        kind=SourceKind.LOCAL_ENGINE,
        severity=severity,
        title_key="k",
        title_en="t",
        weight=weight,
        decisive=decisive,
        data=data or {},
    )


def test_decisive_signal_is_dangerous_with_floor() -> None:
    verdict, risk, _key, _reason = score(
        [_sig(Severity.CRITICAL, weight=100, decisive=True)],
        had_authoritative_source=True,
    )
    assert verdict is Verdict.DANGEROUS
    assert risk >= 80


def test_medium_signal_is_suspicious() -> None:
    verdict, risk, _key, _reason = score(
        [_sig(Severity.MEDIUM, weight=30)], had_authoritative_source=True
    )
    assert verdict is Verdict.SUSPICIOUS
    assert 40 <= risk <= 79


def test_safe_requires_authoritative_source() -> None:
    clean = [_sig(Severity.INFO, weight=-20, source="ml", data={"probability": 0.01})]
    verdict, risk, _key, _reason = score(clean, had_authoritative_source=True)
    assert verdict is Verdict.SAFE
    assert risk <= 20


def test_unknown_without_authoritative_source() -> None:
    clean = [_sig(Severity.INFO, weight=0, source="ml", data={"probability": 0.01})]
    verdict, _risk, _key, _reason = score(clean, had_authoritative_source=False)
    assert verdict is Verdict.UNKNOWN


def test_trusted_signature_suppresses_packing_escalation() -> None:
    signals = [
        _sig(Severity.MEDIUM, weight=30, source="static", data={"packing_only": True}),
        _sig(
            Severity.INFO,
            weight=-25,
            source="signature",
            data={"valid_trusted_signature": True},
        ),
    ]
    verdict, _risk, _key, _reason = score(signals, had_authoritative_source=True)
    assert verdict is not Verdict.SUSPICIOUS


def test_dangerous_beats_suspicious() -> None:
    signals = [
        _sig(Severity.MEDIUM, weight=30),
        _sig(Severity.CRITICAL, weight=100, decisive=True),
    ]
    verdict, _risk, _key, _reason = score(signals, had_authoritative_source=True)
    assert verdict is Verdict.DANGEROUS
