"""URL pipeline (§7) end-to-end with network calls stubbed.

Providers are skipped via a keyless keyring; RDAP/TLS/redirect network calls are
monkeypatched to canned results so the stage wiring and scoring are exercised
without touching the network (§13).
"""

from __future__ import annotations

import pytest

import prescan.core.config as config_mod
import prescan.core.pipeline as pipeline_mod
from prescan.core.config import AppConfig
from prescan.core.models import ScanRequest, StageStatus, TargetKind, Verdict
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
