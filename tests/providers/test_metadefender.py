"""Tests for the MetaDefender provider via respx (never real network, §13)."""

from __future__ import annotations

import httpx
import pytest
import respx

from prescan.core.models import Availability, Verdict
from prescan.core.providers.metadefender import MetaDefenderProvider
from prescan.core.ratelimit import RateLimiter
from prescan.core.scoring import score

_SHA = "b" * 64
_URL = f"https://api.metadefender.com/v4/hash/{_SHA}"


def _provider(key: str | None = "dummy-key") -> MetaDefenderProvider:
    return MetaDefenderProvider(key, RateLimiter(), allow_network=True)


def _body(detected: int, total: int = 40) -> dict[str, object]:
    return {"scan_results": {"total_detected_avs": detected, "total_avs": total}}


@respx.mock
@pytest.mark.asyncio
async def test_many_detections_decisive() -> None:
    respx.get(_URL).mock(return_value=httpx.Response(200, json=_body(9)))
    signals = await _provider().lookup_hash(_SHA)
    assert signals[0].decisive is True
    verdict, _risk, _k, _r = score(signals, had_authoritative_source=True)
    assert verdict is Verdict.DANGEROUS


@respx.mock
@pytest.mark.asyncio
async def test_clean_is_authoritative() -> None:
    respx.get(_URL).mock(return_value=httpx.Response(200, json=_body(0)))
    signals = await _provider().lookup_hash(_SHA)
    assert signals[0].data["authoritative_clean"] is True


@respx.mock
@pytest.mark.asyncio
async def test_not_found_body_is_ignored() -> None:
    respx.get(_URL).mock(return_value=httpx.Response(200, json={"error": {"code": 404003}}))
    assert await _provider().lookup_hash(_SHA) == []


@pytest.mark.asyncio
async def test_missing_key_is_no_key() -> None:
    availability, _detail = await _provider(None).availability()
    assert availability is Availability.NO_KEY
