"""VirusTotal provider: reputation by file hash (only the hash leaves, §6.2)."""

from __future__ import annotations

import asyncio
import base64
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

import httpx
import structlog
from tenacity import AsyncRetrying, retry_if_exception_type, stop_after_attempt, wait_exponential

from prescan.core.models import Availability, Severity, Signal, SourceKind, UploadOutcome
from prescan.core.providers.base import HttpProvider
from prescan.core.scoring import weight

log = structlog.get_logger(__name__)

_API = "https://www.virustotal.com/api/v3/files/{sha256}"
_URL_API = "https://www.virustotal.com/api/v3/urls/{url_id}"
_UPLOAD_API = "https://www.virustotal.com/api/v3/files"
_UPLOAD_URL_API = "https://www.virustotal.com/api/v3/files/upload_url"
_ANALYSES_API = "https://www.virustotal.com/api/v3/analyses/{analysis_id}"
_VT_CAP = 90  # §8.4: vt_malicious_per_hit multiplied by hits, capped at 90
#: Direct POST /files accepts up to 32 MiB; larger files use a one-time upload URL
#: (up to 650 MiB, = max_upload_bytes). Source: docs.virustotal.com/reference/files-scan.
_DIRECT_UPLOAD_MAX = 32 * 1024 * 1024
#: Cap on waiting for the analysis after the bytes are sent (§6 stage 13: 30-180 s).
_ANALYSIS_WAIT_CAP = 180.0


class _RateLimitedError(Exception):
    """VirusTotal returned 429; retried via tenacity, never crashes the upload."""


class _UploadFailedError(Exception):
    """Upload could not be sent. Carries only a status code + a fixed reason so no
    URL / response text (which may hold the one-time upload URL) reaches a log."""

    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


class VirusTotalProvider(HttpProvider):
    """VirusTotal v3 file lookup by SHA-256."""

    name: ClassVar[str] = "virustotal"
    kind: ClassVar[SourceKind] = SourceKind.CLOUD_REPUTATION
    stage_id: ClassVar[str] = "reputation"
    requires_key: ClassVar[bool] = True
    sends_full_url: ClassVar[bool] = True  # full URL leaves; 'only send hashes' disables it
    supports_upload: ClassVar[bool] = True
    max_upload_bytes: ClassVar[int] = 650 * 1024 * 1024

    async def lookup_hash(self, sha256: str) -> list[Signal]:
        """Return reputation signals for a hash. Unknown hash -> no signal."""
        response = await self._request(
            "GET",
            _API.format(sha256=sha256),
            headers={"x-apikey": self._api_key or ""},
        )
        if response is None:  # 404: VirusTotal does not know this file
            return []
        try:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            return self._file_signals_from_stats(stats)
        except (ValueError, KeyError, TypeError) as exc:
            log.warning("virustotal.parse_failed", error=str(exc))
            return []

    def _file_signals_from_stats(self, stats: dict[str, Any]) -> list[Signal]:
        """Turn a VirusTotal stats block into scoring signals (§8.2/§8.3).

        The single place file reputation becomes signals -- shared by lookup_hash and
        upload_file, so identical stats always yield an identical verdict and signals.
        """
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        # Denominator = only engines that rendered a verdict. failure / timeout /
        # confirmed-timeout / type-unsupported are excluded so "0 of N" is honest.
        total = malicious + suspicious + harmless + undetected
        if malicious >= 4:
            return [self._detection(malicious, total, decisive=True, severity=Severity.CRITICAL)]
        if malicious >= 1:
            return [self._detection(malicious, total, decisive=False, severity=Severity.MEDIUM)]
        if harmless + undetected > 0:
            # Known to VirusTotal and clean: an authoritative clean source (§8.3).
            return [
                self._signal(
                    severity=Severity.INFO,
                    title_key="signal.vt.clean",
                    title_en=f"VirusTotal: 0/{total} engines flagged this file",
                    weight=weight("reputation", "vt_known_clean", -20),
                    data={"malicious": 0, "total": total, "authoritative_clean": True},
                )
            ]
        # No engine could analyse it (e.g. an unsupported type): not clean, just
        # unknown. No authoritative_clean -> it can never turn into a green verdict.
        return [
            self._signal(
                severity=Severity.INFO,
                title_key="signal.vt.unanalyzable",
                title_en="VirusTotal: no engine could analyze this file",
                data={"malicious": 0, "total": 0},
            )
        ]

    async def lookup_url(self, url: str) -> list[Signal]:
        """VirusTotal URL reputation (§7 stage 3). Unknown URL -> no signal."""
        url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
        response = await self._request(
            "GET",
            _URL_API.format(url_id=url_id),
            headers={"x-apikey": self._api_key or ""},
        )
        if response is None:
            return []
        try:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = int(stats.get("malicious", 0))
            total = sum(int(v) for v in stats.values())
        except (ValueError, KeyError, TypeError) as exc:
            log.warning("virustotal.url_parse_failed", error=str(exc))
            return []
        if malicious >= 4:
            return [self._detection(malicious, total, decisive=True, severity=Severity.CRITICAL)]
        if malicious >= 1:
            return [self._detection(malicious, total, decisive=False, severity=Severity.MEDIUM)]
        # Known to VirusTotal and clean: the authoritative-clean source for URLs (§8.3),
        # mirroring lookup_hash. An *unknown* URL is a 404 above -> no signal, so it can
        # never be cleared to SAFE on VirusTotal's silence.
        return [
            self._signal(
                severity=Severity.INFO,
                title_key="signal.vt.url_clean",
                title_en=f"VirusTotal: 0/{total} engines flagged this URL",
                weight=weight("reputation", "vt_known_clean", -20),
                data={"malicious": 0, "total": total, "authoritative_clean": True},
            )
        ]

    def _detection(
        self, malicious: int, total: int, *, decisive: bool, severity: Severity
    ) -> Signal:
        per_hit = weight("reputation", "vt_malicious_per_hit", 22)
        return self._signal(
            severity=severity,
            title_key="signal.vt.detection",
            title_en=f"VirusTotal: {malicious}/{total} engines flagged this file",
            detail=f"{malicious}/{total}",
            weight=min(_VT_CAP, per_hit * malicious),
            decisive=decisive,
            # §8.2: 1..3 detections escalate to SUSPICIOUS (>=4 is decisive above).
            data={"malicious": malicious, "total": total, "escalates": not decisive},
        )

    # ---- stage 13: upload for a fresh scan (only after explicit consent) ---- #
    async def upload_file(
        self,
        path: Path,
        *,
        cancel: asyncio.Event | None = None,
        now: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> UploadOutcome:
        """Upload the file for a fresh cloud scan (stage 13) and await the verdict.

        Streams the file (never loads it whole, §6.2/point 12), retries transient/429
        failures via tenacity, and polls ``/analyses`` paced by the shared 4/min limiter
        (VirusTotal public limit) up to a 180 s **monotonic** cap. ``sent``/``sent_at``
        are set the instant the bytes leave and never cleared, so a later timeout,
        cancel or error still reports honestly that the file left the machine.

        The result runs through the very same ``_file_signals_from_stats`` as
        ``lookup_hash``, so identical stats give an identical verdict.
        """
        cancel = cancel or asyncio.Event()
        sleep = sleep or asyncio.sleep
        if not self._api_key:
            return UploadOutcome(availability=Availability.NO_KEY, detail="API key not configured")
        if not self._api_key.isascii():
            return UploadOutcome(
                availability=Availability.ERROR,
                detail="API key looks invalid (non-ASCII characters)",
            )
        try:
            analysis_id = await self._send_for_analysis(path, sleep=sleep)
        except _UploadFailedError as exc:
            # The bytes never left -> no sent flag. Log only a fixed stage label and a
            # status code; never the URL, exception text or body (they can carry the
            # one-time upload URL, which is a secret, §10.5/point 12).
            log.warning("vt.upload_send_failed", stage="cloud_upload", status=exc.status)
            return UploadOutcome(availability=Availability.ERROR, detail=exc.reason)

        sent_at = datetime.now(UTC)  # the file has left the machine (point 8)
        signals, detail = await self._await_analysis(
            analysis_id, cancel=cancel, deadline=now() + _ANALYSIS_WAIT_CAP, now=now
        )
        if signals is None:
            log.info("vt.upload_no_result", stage="cloud_upload", reason=detail)
            return UploadOutcome(
                sent=True, sent_at=sent_at, availability=Availability.ERROR, detail=detail
            )
        return UploadOutcome(
            sent=True,
            sent_at=sent_at,
            signals=signals,
            availability=Availability.READY,
            detail="completed",
        )

    async def _send_for_analysis(
        self, path: Path, *, sleep: Callable[[float], Awaitable[None]]
    ) -> str:
        """Send the file (direct or via a one-time upload URL) and return analysis id."""
        try:
            if path.stat().st_size <= _DIRECT_UPLOAD_MAX:
                response = await self._post_file(_UPLOAD_API, path, with_key=True, sleep=sleep)
            else:
                upload_url = await self._get_upload_url()
                response = await self._post_file(upload_url, path, with_key=False, sleep=sleep)
            return str(response.json()["data"]["id"])
        except _RateLimitedError as exc:
            raise _UploadFailedError(429, "VirusTotal rate limit reached (429)") from exc
        except httpx.HTTPStatusError as exc:
            raise _UploadFailedError(exc.response.status_code, "upload was rejected") from exc
        except (httpx.TransportError, ValueError, KeyError, TypeError) as exc:
            raise _UploadFailedError(0, "upload failed") from exc

    async def _get_upload_url(self) -> str:
        """Fetch a one-time signed upload URL for files larger than 32 MiB."""
        response = await self._request(
            "GET", _UPLOAD_URL_API, headers={"x-apikey": self._api_key or ""}
        )
        if response is None:  # 404
            raise _UploadFailedError(404, "could not obtain an upload URL")
        return str(response.json()["data"])

    async def _post_file(
        self,
        url: str,
        path: Path,
        *,
        with_key: bool,
        sleep: Callable[[float], Awaitable[None]],
    ) -> httpx.Response:
        """Stream the file to ``url``, retrying transient errors and 429 via tenacity.

        The file is re-opened on each attempt and handed to httpx as a file object, so
        it streams in chunks -- a 650 MiB file never lands in memory (point 12).
        """
        headers = {"x-apikey": self._api_key or ""} if with_key else {}
        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(3),
            wait=wait_exponential(multiplier=1, min=1, max=10),
            retry=retry_if_exception_type((httpx.TransportError, _RateLimitedError)),
            sleep=sleep,  # injectable so tests pace deterministically, no real waits
            reraise=True,
        ):
            with attempt:
                await self._limiter.acquire(self.name)
                with path.open("rb") as handle:  # stream + re-open per attempt (point 12)
                    timeout = httpx.Timeout(self._timeout_s, connect=15.0)
                    async with httpx.AsyncClient(timeout=timeout) as client:
                        response = await client.post(
                            url, files={"file": (path.name, handle)}, headers=headers
                        )
                if response.status_code == httpx.codes.TOO_MANY_REQUESTS:
                    raise _RateLimitedError
                response.raise_for_status()
                return response
        raise AssertionError("unreachable")  # pragma: no cover - reraise=True guarantees exit

    async def _await_analysis(
        self,
        analysis_id: str,
        *,
        cancel: asyncio.Event,
        deadline: float,
        now: Callable[[], float],
    ) -> tuple[list[Signal] | None, str]:
        """Poll ``/analyses/{id}`` until completed, the monotonic cap, or cancel.

        Each poll takes a token from the shared VirusTotal bucket (public 4/min limit),
        so polls are spaced ~15 s and never burn the user's daily quota (point 13).
        """
        url = _ANALYSES_API.format(analysis_id=analysis_id)
        headers = {"x-apikey": self._api_key or ""}
        while True:
            if cancel.is_set():
                return None, "cancelled while awaiting the analysis"
            await self._limiter.acquire(self.name)
            try:
                timeout = httpx.Timeout(self._timeout_s, connect=15.0)
                async with httpx.AsyncClient(timeout=timeout) as client:
                    response: httpx.Response | None = await client.get(url, headers=headers)
            except httpx.TransportError:
                response = None
            if response is not None and response.status_code == httpx.codes.OK:
                attributes = response.json().get("data", {}).get("attributes", {})
                if attributes.get("status") == "completed":  # queued/in-progress never score
                    return self._file_signals_from_stats(attributes.get("stats", {})), "completed"
            # queued / in-progress / 429 / transient error -> keep waiting until the cap.
            if now() >= deadline:
                return None, "result not received in 180 s"

    async def remaining_quota(self) -> str | None:
        # Would cost an extra request against the user's 500/day quota; not worth it.
        return None
