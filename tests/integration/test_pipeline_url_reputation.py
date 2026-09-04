"""URL reputation end-to-end: provider response -> signal -> verdict (respx, no network).

The §8.3 URL fix and the privacy gate were covered per-function; these run a URL through
the *whole* pipeline and assert the final verdict, so the chain (VirusTotal answer ->
authoritative_clean signal -> SAFE) is proven, not just believed. RDAP / TLS / redirect
network calls are monkeypatched to clean canned results; every provider HTTP call goes
through respx.
"""

from __future__ import annotations

import httpx
import pytest
import respx

import prescan.core.config as config_mod
import prescan.core.pipeline as pipeline_mod
from prescan.core.config import AppConfig
from prescan.core.models import Availability, ScanRequest, StageStatus, TargetKind, Verdict
from prescan.core.pipeline import Pipeline
from prescan.core.url.inspector import InspectResult
from prescan.core.url.tls import TlsResult

_URL = "https://example.com/"


def _patch_clean_local(monkeypatch: pytest.MonkeyPatch) -> None:
    """Old domain, valid TLS, no redirect change, and a key for every provider."""

    async def old_domain(_domain: str, *, timeout_s: float = 15.0) -> int:
        return 3650

    async def valid_tls(_host: str, port: int = 443, *, timeout_s: float = 15.0) -> TlsResult:
        return TlsResult(valid=True, host_match=True, error=None)

    async def plain_inspect(url: str, **_kw: object) -> InspectResult:
        return InspectResult(
            final_url=url, redirect_chain=[url], registrable_changed=False, http_status=200
        )

    monkeypatch.setattr(pipeline_mod, "domain_age_days", old_domain)
    monkeypatch.setattr(pipeline_mod, "inspect_tls", valid_tls)
    monkeypatch.setattr(pipeline_mod, "inspect_url", plain_inspect)
    monkeypatch.setattr(config_mod, "get_api_key", lambda _pid: "k")


def _mock_virustotal_clean() -> None:
    respx.get(host="www.virustotal.com").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 70}}}
            },
        )
    )


def _mock_urlscan_clean() -> None:
    respx.get(host="urlscan.io").mock(return_value=httpx.Response(200, json={"results": []}))


def _mock_urlhaus(*, listed: bool) -> None:
    body = (
        {"query_status": "ok", "url_status": "online", "threat": "malware_download"}
        if listed
        else {"query_status": "no_results"}
    )
    respx.post(host="urlhaus-api.abuse.ch").mock(return_value=httpx.Response(200, json=body))


def _mock_safebrowsing_clean() -> None:
    respx.get(host="safebrowsing.googleapis.com").mock(return_value=httpx.Response(200, json={}))


async def _scan(config: AppConfig) -> object:
    request = ScanRequest(target_kind=TargetKind.URL, url=_URL, allow_network=True)
    return await Pipeline(config).run(request)


@respx.mock
@pytest.mark.asyncio
async def test_url_safe_via_virustotal_authoritative_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_clean_local(monkeypatch)
    _mock_virustotal_clean()  # known & malicious == 0 -> authoritative_clean
    _mock_urlscan_clean()
    _mock_urlhaus(listed=False)
    _mock_safebrowsing_clean()

    report = await _scan(AppConfig.load())  # only_send_hashes defaults False -> all run

    assert report.verdict is Verdict.SAFE, report.verdict_reason_en
    assert not report.incomplete


@respx.mock
@pytest.mark.asyncio
async def test_url_unknown_when_only_send_hashes_disables_full_url_sources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_clean_local(monkeypatch)
    _mock_safebrowsing_clean()  # the only source allowed to run under the privacy setting

    config = AppConfig.load()
    config.only_send_hashes = True
    report = await _scan(config)

    assert report.verdict is Verdict.UNKNOWN
    disabled = {
        s.stage_id
        for s in report.stages
        if s.title_key == "stage.url_reputation" and s.availability is Availability.DISABLED
    }
    assert disabled == {"virustotal", "urlscan", "urlhaus"}
    assert {"virustotal", "urlscan", "urlhaus"} <= set(report.unavailable_sources)


@respx.mock
@pytest.mark.asyncio
async def test_url_dangerous_via_urlhaus_active_listing(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_clean_local(monkeypatch)
    _mock_virustotal_clean()
    _mock_urlscan_clean()
    _mock_urlhaus(listed=True)  # active malware URL -> decisive DANGEROUS
    _mock_safebrowsing_clean()

    report = await _scan(AppConfig.load())

    assert report.verdict is Verdict.DANGEROUS, report.verdict_reason_en
    urlhaus = next(s for s in report.stages if s.stage_id == "urlhaus")
    assert urlhaus.status is StageStatus.DONE
