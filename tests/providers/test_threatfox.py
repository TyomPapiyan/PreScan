"""Tests for the ThreatFox provider via respx (never real network, §13)."""

from __future__ import annotations

import httpx
import pytest
import respx

from prescan.core.models import Availability, Verdict
from prescan.core.providers.threatfox import ThreatFoxProvider
from prescan.core.ratelimit import RateLimiter
from prescan.core.scoring import score

_SHA = "e" * 64
_URL = "https://threatfox-api.abuse.ch/api/v1/"


def _provider(key: str | None = "dummy-key") -> ThreatFoxProvider:
    return ThreatFoxProvider(key, RateLimiter(), allow_network=True)


@respx.mock
@pytest.mark.asyncio
async def test_high_confidence_ioc_is_decisive() -> None:
    body = {
        "query_status": "ok",
        "data": [{"confidence_level": 90, "malware_printable": "Cobalt Strike"}],
    }
    respx.post(_URL).mock(return_value=httpx.Response(200, json=body))
    signals = await _provider().lookup_hash(_SHA)
    assert signals[0].decisive is True
    verdict, _risk, _k, _r = score(signals, had_authoritative_source=True)
    assert verdict is Verdict.DANGEROUS


@respx.mock
@pytest.mark.asyncio
async def test_low_confidence_is_not_decisive() -> None:
    body = {
        "query_status": "ok",
        "data": [{"confidence_level": 40, "malware_printable": "Unknown"}],
    }
    respx.post(_URL).mock(return_value=httpx.Response(200, json=body))
    signals = await _provider().lookup_hash(_SHA)
    assert signals[0].decisive is False


@respx.mock
@pytest.mark.asyncio
async def test_no_result_is_empty() -> None:
    body = {"query_status": "no_result", "data": []}
    respx.post(_URL).mock(return_value=httpx.Response(200, json=body))
    assert await _provider().lookup_hash(_SHA) == []


@pytest.mark.asyncio
async def test_missing_key_is_no_key() -> None:
    availability, _detail = await _provider(None).availability()
    assert availability is Availability.NO_KEY
