"""Pipeline stage 11 (reputation) end-to-end with all providers mocked (respx).

Exercises provider wiring, per-provider stages and scoring from cloud signals
without any real network (§13). Keys are injected via monkeypatch so the test
does not depend on the developer's keyring.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx

import prescan.core.config as config_mod
from prescan.core.config import AppConfig
from prescan.core.models import ScanRequest, StageStatus, TargetKind, Verdict
from prescan.core.pipeline import Pipeline

_VT_MALICIOUS = {"data": {"attributes": {"last_analysis_stats": {"malicious": 10, "harmless": 60}}}}
_MD_CLEAN = {"scan_results": {"total_detected_avs": 0, "total_avs": 40}}
_MB_NONE = {"query_status": "hash_not_found", "data": []}
_TF_NONE = {"query_status": "no_result", "data": []}


@respx.mock
@pytest.mark.asyncio
async def test_reputation_stage_runs_and_scores(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(config_mod, "get_api_key", lambda _pid: "dummy-key")

    respx.route(method="GET", host="www.virustotal.com").mock(
        return_value=httpx.Response(200, json=_VT_MALICIOUS)
    )
    respx.route(method="GET", host="api.metadefender.com").mock(
        return_value=httpx.Response(200, json=_MD_CLEAN)
    )
    respx.route(method="POST", host="mb-api.abuse.ch").mock(
        return_value=httpx.Response(200, json=_MB_NONE)
    )
    respx.route(method="POST", host="threatfox-api.abuse.ch").mock(
        return_value=httpx.Response(200, json=_TF_NONE)
    )

    target = tmp_path / "sample.bin"
    target.write_bytes(b"reputation test payload")
    request = ScanRequest(target_kind=TargetKind.FILE, file_path=target, allow_network=True)

    report = await Pipeline(AppConfig.load()).run(request)

    rep_stages = {s.stage_id: s for s in report.stages if s.title_key == "stage.reputation"}
    assert rep_stages["virustotal"].status is StageStatus.DONE
    assert rep_stages["metadefender"].status is StageStatus.DONE
    # VirusTotal reported 10 detections -> a decisive DANGEROUS verdict (§8.1).
    assert report.verdict is Verdict.DANGEROUS
    assert any(s.source == "virustotal" and s.decisive for s in report.signals)


@respx.mock
@pytest.mark.asyncio
async def test_no_key_providers_are_skipped_not_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(config_mod, "get_api_key", lambda _pid: None)

    target = tmp_path / "sample.bin"
    target.write_bytes(b"no keys here")
    request = ScanRequest(target_kind=TargetKind.FILE, file_path=target, allow_network=True)

    report = await Pipeline(AppConfig.load()).run(request)

    rep_stages = [s for s in report.stages if s.title_key == "stage.reputation"]
    assert rep_stages, "reputation providers should appear as stages"
    assert all(s.status is StageStatus.SKIPPED for s in rep_stages)
    assert all(s.availability.value == "no_key" for s in rep_stages)
    for name in ("virustotal", "metadefender", "malwarebazaar", "threatfox"):
        assert name in report.unavailable_sources
