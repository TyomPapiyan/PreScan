"""Client-side per-provider rate limiting (token bucket).

Public reputation APIs cap request rates; exceeding them returns 429 to the
user. We queue and wait instead (§12 M2): the VirusTotal public API allows four
lookups per minute, so its bucket refills one token every 15 seconds and holds
no burst, guaranteeing we never trip 429 even under back-to-back calls.
"""

from __future__ import annotations

import asyncio
import time
from typing import Final

import structlog

log = structlog.get_logger(__name__)


class TokenBucket:
    """An async token bucket. ``acquire`` blocks until a token is available.

    The refill lock is held across the wait so concurrent callers are serialised
    into a queue rather than all waking at once.
    """

    def __init__(self, rate_per_minute: float, capacity: float = 1.0) -> None:
        if rate_per_minute <= 0:
            raise ValueError("rate_per_minute must be positive")
        self._rate_per_sec = rate_per_minute / 60.0
        self._capacity = max(1.0, capacity)
        self._tokens = self._capacity
        self._lock = asyncio.Lock()
        self._last = time.monotonic()

    async def acquire(self) -> None:
        """Consume one token, waiting (queued) until one is available."""
        async with self._lock:
            now = time.monotonic()
            refill = (now - self._last) * self._rate_per_sec
            self._tokens = min(self._capacity, self._tokens + refill)
            self._last = now
            if self._tokens < 1.0:
                wait = (1.0 - self._tokens) / self._rate_per_sec
                await asyncio.sleep(wait)
                self._tokens = 0.0
                self._last = time.monotonic()
            else:
                self._tokens -= 1.0


#: Default per-provider limits. VirusTotal public tier: 4 requests/minute,
#: strict spacing (capacity 1) so six back-to-back calls span >60s, never 429.
_DEFAULT_LIMITS: Final[dict[str, tuple[float, float]]] = {
    "virustotal": (4.0, 1.0),
    "metadefender": (10.0, 2.0),
    "malwarebazaar": (30.0, 5.0),
    "threatfox": (30.0, 5.0),
    "safebrowsing": (60.0, 10.0),
    "urlscan": (60.0, 5.0),
    "urlhaus": (60.0, 10.0),
}


class RateLimiter:
    """Registry of one token bucket per provider id."""

    def __init__(self, limits: dict[str, tuple[float, float]] | None = None) -> None:
        self._limits = limits or _DEFAULT_LIMITS
        self._buckets: dict[str, TokenBucket] = {}

    def bucket(self, provider: str) -> TokenBucket:
        """Return (creating on first use) the bucket for a provider."""
        if provider not in self._buckets:
            rate, capacity = self._limits.get(provider, (60.0, 5.0))
            self._buckets[provider] = TokenBucket(rate, capacity)
        return self._buckets[provider]

    async def acquire(self, provider: str) -> None:
        """Wait for a token for ``provider`` before its next request."""
        await self.bucket(provider).acquire()
