"""Contract every cloud provider must satisfy."""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar, Protocol, runtime_checkable

import httpx
import structlog
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from prescan.core.models import Availability, Signal, SourceKind
from prescan.core.ratelimit import RateLimiter

log = structlog.get_logger(__name__)


@runtime_checkable
class Provider(Protocol):
    name: ClassVar[str]
    kind: ClassVar[SourceKind]
    stage_id: ClassVar[str]
    requires_key: ClassVar[bool]
    supports_upload: ClassVar[bool]
    max_upload_bytes: ClassVar[int]
    #: True if this source receives the *full* URL on ``lookup_url`` (VirusTotal,
    #: urlscan, URLhaus). The "only send hashes" privacy setting disables these for
    #: URL scans; Safe Browsing (hash prefixes) sets it False and stays on.
    sends_full_url: ClassVar[bool]

    async def availability(self) -> tuple[Availability, str]: ...

    async def lookup_hash(self, sha256: str) -> list[Signal]:
        """Reputation by hash. The file itself must NOT leave the machine here."""
        ...

    async def lookup_url(self, url: str) -> list[Signal]: ...

    async def upload_file(self, path: Path) -> list[Signal]:
        """Stage 3 only. Called exclusively after explicit user consent."""
        ...

    async def remaining_quota(self) -> str | None:
        """Human-readable quota left, or None when the API does not report it."""
        ...


class HttpProvider:
    """Shared base for HTTP reputation providers.

    Handles availability (OFFLINE / NO_KEY / READY), rate-limited requests with
    retry, and safe defaults for methods a given provider does not implement.
    Concrete providers set the ClassVars and override the lookups they support.
    Providers must never send the file body on ``lookup_hash`` — only the hash.
    """

    name: ClassVar[str] = "http"
    kind: ClassVar[SourceKind] = SourceKind.CLOUD_REPUTATION
    stage_id: ClassVar[str] = "reputation"
    requires_key: ClassVar[bool] = True
    supports_upload: ClassVar[bool] = False
    max_upload_bytes: ClassVar[int] = 0
    sends_full_url: ClassVar[bool] = False  # overridden True by full-URL providers

    def __init__(
        self,
        api_key: str | None,
        limiter: RateLimiter,
        *,
        allow_network: bool = True,
        timeout_s: float = 30.0,
    ) -> None:
        self._api_key = api_key
        self._limiter = limiter
        self._allow_network = allow_network
        self._timeout_s = timeout_s

    async def availability(self) -> tuple[Availability, str]:
        """OFFLINE (no network), NO_KEY (missing), ERROR (unusable key), else READY."""
        if not self._allow_network:
            return Availability.OFFLINE, "network disabled"
        if self.requires_key and not self._api_key:
            return Availability.NO_KEY, "API key not configured"
        if self.requires_key and self._api_key and not self._api_key.isascii():
            # A non-ASCII key cannot even be sent as an HTTP header (httpx encodes
            # header values as ASCII), so catch it here and degrade to a clear ERROR
            # instead of crashing mid-request with an UnicodeEncodeError traceback.
            return Availability.ERROR, "API key looks invalid (non-ASCII characters)"
        return Availability.READY, "ready"

    async def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, str | list[str]] | None = None,
        data: dict[str, str] | None = None,
    ) -> httpx.Response | None:
        """Rate-limited HTTP request with retry. Returns None on 404."""
        await self._limiter.acquire(self.name)

        @retry(
            stop=stop_after_attempt(3),
            wait=wait_exponential(multiplier=1, min=1, max=10),
            retry=retry_if_exception_type(httpx.TransportError),
            reraise=True,
        )
        async def _send() -> httpx.Response:
            timeout = httpx.Timeout(self._timeout_s, connect=15.0)
            async with httpx.AsyncClient(timeout=timeout) as client:
                return await client.request(method, url, headers=headers, params=params, data=data)

        response = await _send()
        if response.status_code == httpx.codes.NOT_FOUND:
            return None
        response.raise_for_status()
        return response

    def _signal(self, **kwargs: Any) -> Signal:
        """Build a Signal defaulting source/kind to this provider."""
        kwargs.setdefault("source", self.name)
        kwargs.setdefault("kind", self.kind)
        return Signal(**kwargs)

    async def lookup_hash(self, sha256: str) -> list[Signal]:
        return []

    async def lookup_url(self, url: str) -> list[Signal]:
        return []

    async def upload_file(self, path: Path) -> list[Signal]:
        return []

    async def remaining_quota(self) -> str | None:
        return None
