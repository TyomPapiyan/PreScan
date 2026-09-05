"""URL pipeline (§7) end-to-end with network calls stubbed.

Providers are skipped via a keyless keyring; RDAP/TLS/redirect network calls are
monkeypatched to canned results so the stage wiring and scoring are exercised
without touching the network (§13).
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

import prescan.core.config as config_mod
import prescan.core.pipeline as pipeline_mod
from prescan.core.config import AppConfig
from prescan.core.models import (
    Availability,
    ScanRequest,
    Severity,
    Signal,
    SourceKind,
    StageStatus,
    TargetKind,
    Verdict,
)
from prescan.core.pipeline import Pipeline
from prescan.core.url.inspector import InspectResult
from prescan.core.url.tls import TlsResult


@pytest.mark.asyncio
async def test_url_pipeline_scores_risky_signals(monkeypatch: pytest.MonkeyPatch) -> None:
    # No provider keys -> URL providers are SKIPPED (NO_KEY), no network.
    monkeypatch.setattr(config_mod, "get_api_key", lambda _pid: None)

    async def fake_age(_domain: str, *, timeout_s: float = 15.0) -> int:
        return 5  # young domain -> risk

    async def fake_tls(_host: str, port: int = 443, *, timeout_s: float = 15.0) -> TlsResult:
        return TlsResult(valid=False, host_match=False, error="expired")

    async def fake_inspect(url: str, **_kw: object) -> InspectResult:
        return InspectResult(
            final_url="https://evil.ru/",
            redirect_chain=["https://evil.ru/"],
            registrable_changed=True,
            http_status=200,
        )

    monkeypatch.setattr(pipeline_mod, "domain_age_days", fake_age)
    monkeypatch.setattr(pipeline_mod, "inspect_tls", fake_tls)
    monkeypatch.setattr(pipeline_mod, "inspect_url", fake_inspect)

    request = ScanRequest(
        target_kind=TargetKind.URL, url="https://good-site.com/login", allow_network=True
    )
    report = await Pipeline(AppConfig.load()).run(request)

    stage_ids = {s.stage_id for s in report.stages}
    assert {"url_normalize", "url_heuristics", "domain_age", "tls", "redirects"} <= stage_ids
    assert report.url is not None
    assert report.url.domain_age_days == 5
    assert report.url.tls_valid is False
    # Young domain + invalid TLS + registrable-domain change -> SUSPICIOUS.
    assert report.verdict is Verdict.SUSPICIOUS

    rep_stages = [s for s in report.stages if s.title_key == "stage.url_reputation"]
    assert rep_stages and all(s.status is StageStatus.SKIPPED for s in rep_stages)


@pytest.mark.asyncio
async def test_url_pipeline_offline_only_local(monkeypatch: pytest.MonkeyPatch) -> None:
    request = ScanRequest(
        target_kind=TargetKind.URL, url="https://example.com/", allow_network=False
    )
    report = await Pipeline(AppConfig.load()).run(request)
    stage_ids = {s.stage_id for s in report.stages}
    assert "url_normalize" in stage_ids
    assert "domain_age" not in stage_ids  # network stages skipped offline
    assert report.verdict in {Verdict.UNKNOWN, Verdict.SAFE}


# --------------------------------------------------------------------------- #
# F0: hash reputation for the downloaded body, with the §8.3 asymmetry
# --------------------------------------------------------------------------- #
class _BodyHash:
    """A hash provider (stage-11 shape) returning canned signals for the body."""

    name = "virustotal"
    kind = SourceKind.CLOUD_REPUTATION
    stage_id = "reputation"
    requires_key = True

    def __init__(self, signals: list[Signal]) -> None:
        self._signals = signals

    async def availability(self) -> tuple[Availability, str]:
        return Availability.READY, "ready"

    async def lookup_hash(self, sha256: str) -> list[Signal]:
        return list(self._signals)


def _benign_url_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, body: list[Signal]) -> None:
    """Wire a benign URL environment + a fake download + a fake body hash provider."""
    monkeypatch.setattr(config_mod, "get_api_key", lambda _pid: None)  # URL providers off

    async def old_age(_domain: str, *, timeout_s: float = 15.0) -> int:
        return 400  # old domain -> no risk signal

    async def good_tls(_host: str, port: int = 443, *, timeout_s: float = 15.0) -> TlsResult:
        return TlsResult(valid=True, host_match=True)

    async def plain_inspect(url: str, **_kw: object) -> InspectResult:
        return InspectResult(
            final_url=url, redirect_chain=[url], registrable_changed=False, http_status=200
        )

    async def no_engines(self: Pipeline, *a: object, **k: object) -> tuple[list[Signal], bool]:
        return [], False

    async def fake_download(url: str, tmp_dir: Path, **_kw: object) -> Path:
        d = Path(tempfile.mkdtemp(dir=tmp_path))
        f = d / "download.bin"
        f.write_bytes(b"payload")
        return f

    monkeypatch.setattr(pipeline_mod, "domain_age_days", old_age)
    monkeypatch.setattr(pipeline_mod, "inspect_tls", good_tls)
    monkeypatch.setattr(pipeline_mod, "inspect_url", plain_inspect)
    monkeypatch.setattr(pipeline_mod, "safe_download", fake_download)
    monkeypatch.setattr(Pipeline, "_run_engines", no_engines)
    monkeypatch.setattr(pipeline_mod, "build_hash_providers", lambda *a, **k: [_BodyHash(body)])


def _url_request() -> ScanRequest:
    return ScanRequest(
        target_kind=TargetKind.URL,
        url="https://good-site.com/file",
        allow_network=True,
        allow_download=True,
    )


@pytest.mark.asyncio
async def test_downloaded_body_known_malicious_makes_url_dangerous(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Point 16: a known-malicious body behind a link is a dangerous link, in full."""
    malicious = Signal(
        source="malwarebazaar",
        kind=SourceKind.CLOUD_REPUTATION,
        severity=Severity.CRITICAL,
        title_key="signal.mb.hit",
        title_en="Known malware sample",
        decisive=True,
        weight=100,
    )
    _benign_url_env(monkeypatch, tmp_path, [malicious])
    report = await Pipeline(AppConfig.load()).run(_url_request())
    assert report.verdict is Verdict.DANGEROUS


@pytest.mark.asyncio
async def test_downloaded_body_clean_by_hash_keeps_url_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Point 17 (the main test): a clean body hash does NOT make the link SAFE.

    A clean hash is authoritative for the file, not for the link -- a URL can serve
    different content -- so the verdict stays UNKNOWN. If this ever turns SAFE, §8.3 is
    broken. It is asserted != SAFE (not just == UNKNOWN) so it cannot pass by accident.
    """
    clean = Signal(
        source="virustotal",
        kind=SourceKind.CLOUD_REPUTATION,
        severity=Severity.INFO,
        title_key="signal.vt.clean",
        title_en="VirusTotal: file known, clean",
        data={"authoritative_clean": True},
    )
    _benign_url_env(monkeypatch, tmp_path, [clean])
    report = await Pipeline(AppConfig.load()).run(_url_request())
    assert report.verdict is not Verdict.SAFE
    assert report.verdict is Verdict.UNKNOWN
    # The clean body signal is present and honestly authoritative-clean about the body...
    body_clean = next(s for s in report.signals if s.data.get("authoritative_clean") is True)
    assert body_clean.data.get("target_scope") == "downloaded_body"  # ...but scoped to the body
