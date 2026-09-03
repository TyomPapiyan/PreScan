"""A non-ASCII API key must degrade to a clear ERROR, never crash the provider.

httpx encodes header values as ASCII, so a stored key with non-ASCII bytes raised an
unhandled UnicodeEncodeError mid-request (the source showed 'error' with a traceback
reason). availability() now catches it up front so the stage is a clean ERROR and the
"Check key" button can say the key looks invalid.
"""

from __future__ import annotations

import pytest

from prescan.core.models import Availability
from prescan.core.providers.virustotal import VirusTotalProvider
from prescan.core.ratelimit import RateLimiter


@pytest.mark.asyncio
async def test_non_ascii_key_yields_error_not_exception() -> None:
    provider = VirusTotalProvider("\x80\x81\x82bad", RateLimiter(), allow_network=True)
    availability, detail = await provider.availability()  # must not raise
    assert availability is Availability.ERROR
    assert "invalid" in detail.lower()


@pytest.mark.asyncio
async def test_plain_ascii_key_is_ready() -> None:
    provider = VirusTotalProvider("a" * 64, RateLimiter(), allow_network=True)
    availability, _detail = await provider.availability()
    assert availability is Availability.READY
