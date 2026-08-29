"""Tests for the VirusTotal provider via respx (never real network, §13)."""

from __future__ import annotations

import httpx
import pytest
import respx

from prescan.core.models import Availability, Verdict
from prescan.core.providers.virustotal import VirusTotalProvider
from prescan.core.ratelimit import RateLimiter
from prescan.core.scoring import score

_SHA = "a" * 64
_URL = f"https://www.virustotal.com/api/v3/files/{_SHA}"


def _provider(key: str | None = "dummy-key") -> VirusTotalProvider:
    return VirusTotalProvider(key, RateLimiter(), allow_network=True)


def _stats(malicious: int) -> dict[str, object]:
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "harmless": 60,
                    "undetected": 11 - 0,
                    "suspicious": 0,
                    "timeout": 0,
                }
            }
        }
    }


@respx.mock
@pytest.mark.asyncio
async def test_many_detections_are_decisive_dangerous() -> None:
    respx.get(_URL).mock(return_value=httpx.Response(200, json=_stats(10)))
    signals = await _provider().lookup_hash(_SHA)
    assert len(signals) == 1
    assert signals[0].decisive is True
    verdict, risk, _k, _r = score(signals, had_authoritative_source=True)
    assert verdict is Verdict.DANGEROUS
    assert risk >= 80


@respx.mock
@pytest.mark.asyncio
async def test_few_detections_are_suspicious() -> None:
    respx.get(_URL).mock(return_value=httpx.Response(200, json=_stats(2)))
    signals = await _provider().lookup_hash(_SHA)
    assert signals[0].decisive is False
    verdict, _risk, _k, _r = score(signals, had_authoritative_source=True)
    assert verdict is Verdict.SUSPICIOUS


@respx.mock
@pytest.mark.asyncio
async def test_known_clean_is_authoritative() -> None:
    respx.get(_URL).mock(return_value=httpx.Response(200, json=_stats(0)))
    signals = await _provider().lookup_hash(_SHA)
    assert signals[0].data["authoritative_clean"] is True
    assert signals[0].weight < 0


@respx.mock
@pytest.mark.asyncio
async def test_unknown_hash_yields_no_signal() -> None:
    respx.get(_URL).mock(return_value=httpx.Response(404))
    assert await _provider().lookup_hash(_SHA) == []


@pytest.mark.asyncio
async def test_missing_key_is_no_key_not_error() -> None:
    availability, _detail = await _provider(None).availability()
    assert availability is Availability.NO_KEY
