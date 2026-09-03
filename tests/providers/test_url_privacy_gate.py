"""The 'only send hashes' privacy setting must disable full-URL sources (§6.2).

With the toggle on, VirusTotal / urlscan / URLhaus (which receive the full URL) are
switched off for a URL scan and marked DISABLED (not OFFLINE / NO_KEY), while Safe
Browsing (hash prefixes) still runs. No real network -- respx, and the disabled
sources are skipped before any request.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
import pytest
import respx

from prescan.core.config import AppConfig
from prescan.core.models import Availability, StageStatus
from prescan.core.pipeline import Pipeline
from prescan.core.providers.safebrowsing import SafeBrowsingProvider
from prescan.core.providers.urlhaus import UrlhausProvider
from prescan.core.providers.urlscan import UrlscanProvider
from prescan.core.providers.virustotal import VirusTotalProvider

if TYPE_CHECKING:
    from prescan.core.ratelimit import RateLimiter


@respx.mock
@pytest.mark.asyncio
async def test_only_send_hashes_disables_full_url_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    config = AppConfig.load()
    config.only_send_hashes = True
    pipeline = Pipeline(config)

    def _providers(limiter: RateLimiter, *, allow_network: bool = True) -> list[object]:
        return [
            SafeBrowsingProvider("k", limiter, allow_network=allow_network),
            UrlscanProvider("k", limiter, allow_network=allow_network),
            UrlhausProvider("k", limiter, allow_network=allow_network),
            VirusTotalProvider("k", limiter, allow_network=allow_network),
        ]

    monkeypatch.setattr("prescan.core.pipeline.build_url_providers", _providers)
    # Only Safe Browsing may reach the network; the full-URL sources are skipped
    # before any request. Empty body => no threats => a clean, successful run.
    sb = respx.get(host="safebrowsing.googleapis.com").mock(
        return_value=httpx.Response(200, json={})
    )

    stages: list = []
    unavailable: list[str] = []
    signals = await pipeline._run_url_providers("https://example.com/", stages, unavailable, None)

    by_id = {s.stage_id: s for s in stages}
    for name in ("virustotal", "urlscan", "urlhaus"):
        assert by_id[name].availability is Availability.DISABLED, name
        assert name in unavailable, f"{name} must be reported as unavailable"
    assert by_id["safebrowsing"].status is StageStatus.DONE  # still ran
    assert "safebrowsing" not in unavailable
    assert sb.called, "Safe Browsing must still run under 'only send hashes'"
    # The 'why this verdict' block must explain the privacy setting.
    assert any(s.source == "privacy" for s in signals)
