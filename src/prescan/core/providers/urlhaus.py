"""abuse.ch URLhaus provider: active malware-URL blocklist (§8.1)."""

from __future__ import annotations

from typing import ClassVar

import structlog

from prescan.core.models import Severity, Signal, SourceKind
from prescan.core.providers.base import HttpProvider
from prescan.core.scoring import weight

log = structlog.get_logger(__name__)

_API = "https://urlhaus-api.abuse.ch/v1/url/"


class UrlhausProvider(HttpProvider):
    """URLhaus lookup. An active malware URL is a decisive DANGEROUS rule (§8.1)."""

    name: ClassVar[str] = "urlhaus"
    kind: ClassVar[SourceKind] = SourceKind.CLOUD_REPUTATION
    stage_id: ClassVar[str] = "url_reputation"
    requires_key: ClassVar[bool] = True
    sends_full_url: ClassVar[bool] = True  # full URL leaves; 'only send hashes' disables it
    supports_upload: ClassVar[bool] = False
    max_upload_bytes: ClassVar[int] = 0

    async def lookup_url(self, url: str) -> list[Signal]:
        """Flag a URL listed in URLhaus, decisively if it is currently online."""
        response = await self._request(
            "POST",
            _API,
            headers={"Auth-Key": self._api_key or ""},
            data={"url": url},
        )
        if response is None:
            return []
        try:
            body = response.json()
        except ValueError as exc:
            log.warning("urlhaus.parse_failed", error=str(exc))
            return []
        if body.get("query_status") != "ok":
            return []

        online = body.get("url_status") == "online"
        threat = str(body.get("threat") or "malware")
        status = str(body.get("url_status") or "unknown")
        return [
            self._signal(
                severity=Severity.CRITICAL if online else Severity.HIGH,
                title_key="signal.urlhaus.hit",
                title_en=f"URLhaus lists this URL as {threat} ({status})",
                detail=threat,
                weight=weight("reputation", "urlhaus_hit", 95),
                decisive=online,
                data={"threat": threat, "status": body.get("url_status")},
            )
        ]
