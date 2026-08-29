"""Tests for core/ratelimit.py, including the §12 VirusTotal pacing guarantee."""

from __future__ import annotations

import time

import httpx
import pytest
import respx

from prescan.core.providers.virustotal import VirusTotalProvider
from prescan.core.ratelimit import RateLimiter, TokenBucket

_SHA = "d" * 64
_URL = f"https://www.virustotal.com/api/v3/files/{_SHA}"
_CLEAN = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 70}}}}


@pytest.mark.asyncio
async def test_token_bucket_spaces_requests() -> None:
    # 600/min => one token every 0.1s, no burst.
    bucket = TokenBucket(rate_per_minute=600, capacity=1)
    start = time.monotonic()
    for _ in range(4):
        await bucket.acquire()
    elapsed = time.monotonic() - start
    assert elapsed >= 0.3  # 3 gaps of ~0.1s after the first immediate token


def test_invalid_rate_rejected() -> None:
    with pytest.raises(ValueError, match="positive"):
        TokenBucket(rate_per_minute=0)


@respx.mock
@pytest.mark.slow
@pytest.mark.asyncio
async def test_virustotal_six_requests_take_over_60s_no_429() -> None:
    """§12/§13: 6 back-to-back VT lookups must span >60s and never 429."""
    respx.get(_URL).mock(return_value=httpx.Response(200, json=_CLEAN))
    provider = VirusTotalProvider("dummy-key", RateLimiter(), allow_network=True)

    start = time.monotonic()
    for _ in range(6):
        signals = await provider.lookup_hash(_SHA)  # mocked 200 -> never 429
        assert signals  # a clean result, not an error
    elapsed = time.monotonic() - start

    assert elapsed > 60, f"expected >60s of client-side pacing, got {elapsed:.1f}s"
