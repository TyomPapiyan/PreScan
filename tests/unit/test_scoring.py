"""Table-driven tests for core/scoring.py — one case per §8.1 and §8.2 rule."""

from __future__ import annotations

from typing import Any

import pytest

from prescan.core.models import Severity, Signal, SourceKind, Verdict
from prescan.core.scoring import score


def _decisive(source: str, title: str, weight: int = 100) -> Signal:
    """A §8.1 hard-rule signal (decisive)."""
    return Signal(
        source=source,
        kind=SourceKind.CLOUD_REPUTATION,
        severity=Severity.CRITICAL,
        title_key="k",
        title_en=title,
        weight=weight,
        decisive=True,
    )


def _escalating(source: str, title: str, weight: int = 30, **data: Any) -> Signal:
    """A §8.2 signal that escalates the verdict to SUSPICIOUS."""
    return Signal(
        source=source,
        kind=SourceKind.STATIC_ANALYSIS,
        severity=Severity.MEDIUM,
        title_key="k",
        title_en=title,
        weight=weight,
        data={"escalates": True, **data},
    )


def _ml(prob: float) -> Signal:
    # Mirror the engine's severity tiers so no_low_or_worse tests are realistic:
    # a 0.24 probability is a LOW-severity signal, which must still not block SAFE.
    severity = Severity.HIGH if prob >= 0.70 else Severity.LOW if prob >= 0.20 else Severity.INFO
    return Signal(
        source="ml",
        kind=SourceKind.ML,
        severity=severity,
        title_key="k",
        title_en="ml",
        data={"probability": prob},
    )


def _trusted_signature() -> Signal:
    return Signal(
        source="signature",
        kind=SourceKind.STATIC_ANALYSIS,
        severity=Severity.INFO,
        title_key="k",
        title_en="trusted",
        weight=-25,
        data={"valid_trusted_signature": True},
    )


# --------------------------------------------------------------------------- #
# §8.1 — one decisive case per hard DANGEROUS rule
# --------------------------------------------------------------------------- #
_DANGEROUS_ROWS = [
    _decisive("clamav", "ClamAV detection"),
    _decisive("defender", "Defender detection"),
    _decisive("malwarebazaar", "MalwareBazaar hit"),
    _decisive("virustotal", "VirusTotal 5/70", weight=90),
    _decisive("metadefender", "MetaDefender 6/40", weight=90),
    _decisive("yara-x", "YARA critical rule", weight=90),
    _decisive("safebrowsing", "Safe Browsing MALWARE", weight=100),
    _decisive("urlhaus", "URLhaus active malware", weight=95),
    _decisive("threatfox", "ThreatFox IOC confidence 90", weight=85),
]


@pytest.mark.parametrize("signal", _DANGEROUS_ROWS, ids=lambda s: s.source)
def test_dangerous_rules(signal: Signal) -> None:
    verdict, risk, _k, _r = score([signal], had_authoritative_source=True)
    assert verdict is Verdict.DANGEROUS
    assert risk >= 80  # §8.1 floor


# --------------------------------------------------------------------------- #
# §8.2 — one escalating case per SUSPICIOUS rule
# --------------------------------------------------------------------------- #
_SUSPICIOUS_ROWS = [
    _escalating("virustotal", "VirusTotal 2/70"),  # 1..3 detections
    _escalating("metadefender", "MetaDefender 3/40"),
    _escalating("static-pe", "High-entropy section", packing_only=True),  # entropy, unsigned
    _escalating("documents", "VBA macros present"),
    _escalating("documents", "Macro auto-executes"),
    _escalating("documents", "Macro obfuscated"),
    _escalating("documents", "PDF JavaScript"),
    _escalating("documents", "PDF embedded file", weight=60),
    _escalating("identify", "Extension mismatch", weight=40),
    _escalating("yara-x", "YARA medium rule", weight=45),
    _escalating("documents", "Password-protected archive with exe", weight=35),
    _escalating("url", "Domain younger than 30 days"),  # URL
    _escalating("url", "Redirect changes registrable domain"),  # URL
    _escalating("url-heuristics", "IDN homograph", weight=45),  # §7.1 HIGH/CRITICAL
    _escalating("url", "TLS certificate invalid"),  # URL
]


@pytest.mark.parametrize("signal", _SUSPICIOUS_ROWS, ids=lambda s: s.title_en)
def test_suspicious_rules(signal: Signal) -> None:
    verdict, risk, _k, _r = score([signal], had_authoritative_source=True)
    assert verdict is Verdict.SUSPICIOUS
    assert 40 <= risk <= 79  # §8.2 clamp


def test_ml_probability_ge_070_is_suspicious() -> None:
    verdict, _risk, _k, _r = score([_ml(0.73)], had_authoritative_source=True)
    assert verdict is Verdict.SUSPICIOUS


# --------------------------------------------------------------------------- #
# §8.1 precedence and §8.6 false-positive guards
# --------------------------------------------------------------------------- #
def test_dangerous_beats_suspicious() -> None:
    verdict, _r, _k, _rr = score(
        [_escalating("documents", "macro"), _decisive("clamav", "detection")],
        had_authoritative_source=True,
    )
    assert verdict is Verdict.DANGEROUS


def test_trusted_signature_suppresses_packing_escalation() -> None:
    signals = [
        _escalating("static-pe", "High entropy", packing_only=True),
        _trusted_signature(),
    ]
    verdict, _r, _k, _rr = score(signals, had_authoritative_source=True)
    assert verdict is not Verdict.SUSPICIOUS


def test_ml_alone_never_dangerous() -> None:
    verdict, _r, _k, _rr = score([_ml(0.99)], had_authoritative_source=True)
    assert verdict is Verdict.SUSPICIOUS  # capped at SUSPICIOUS, never DANGEROUS


def test_no_signature_alone_is_not_suspicious() -> None:
    no_sig = Signal(
        source="signature",
        kind=SourceKind.STATIC_ANALYSIS,
        severity=Severity.INFO,
        title_key="k",
        title_en="unsigned",
        weight=8,
        data={"signed": False},
    )
    verdict, _r, _k, _rr = score([no_sig], had_authoritative_source=True)
    assert verdict is not Verdict.SUSPICIOUS
    assert verdict is not Verdict.DANGEROUS


# --------------------------------------------------------------------------- #
# §8.3 — SAFE requires an authoritative source; otherwise UNKNOWN
# --------------------------------------------------------------------------- #
def test_safe_needs_authoritative_source() -> None:
    clean = [_ml(0.01)]
    verdict, risk, _k, _r = score(clean, had_authoritative_source=True)
    assert verdict is Verdict.SAFE
    assert risk <= 20


def test_unknown_without_authoritative_source() -> None:
    clean = [_ml(0.01)]
    verdict, _risk, _k, _r = score(clean, had_authoritative_source=False)
    assert verdict is Verdict.UNKNOWN


def test_safe_when_ml_absent_but_trusted_signature() -> None:
    verdict, _r, _k, _rr = score([_trusted_signature()], had_authoritative_source=True)
    assert verdict is Verdict.SAFE


def test_trusted_signature_clears_biased_ml_probability() -> None:
    """A trusted signature clears a signed file even when the (zero-authenticode)
    ML probability sits above 0.20 -- the known §16.12 bias must not block SAFE."""
    signals = [_trusted_signature(), _ml(0.24)]
    verdict, risk, _k, _r = score(signals, had_authoritative_source=True)
    assert verdict is Verdict.SAFE
    assert risk <= 20


def test_trusted_signature_does_not_rescue_strongly_malicious_ml() -> None:
    """Trust clears low/ambiguous ML, but a decisive ML score still escalates."""
    verdict, _r, _k, _rr = score([_trusted_signature(), _ml(0.95)], had_authoritative_source=True)
    assert verdict is Verdict.SUSPICIOUS


def test_clean_with_no_sources_is_unknown() -> None:
    verdict, _r, _k, _rr = score([], had_authoritative_source=False)
    assert verdict is Verdict.UNKNOWN
