"""abuse.ch ThreatFox provider: IOC lookup by hash (§8.1, confidence >= 75)."""

from __future__ import annotations

from typing import ClassVar

import structlog

from prescan.core.models import Severity, Signal, SourceKind
from prescan.core.providers.base import HttpProvider
from prescan.core.scoring import weight

log = structlog.get_logger(__name__)

_API = "https://threatfox-api.abuse.ch/api/v1/"
_CONFIDENCE_DECISIVE = 75


class ThreatFoxProvider(HttpProvider):
    """ThreatFox search_hash lookup by SHA-256."""

    name: ClassVar[str] = "threatfox"
    kind: ClassVar[SourceKind] = SourceKind.CLOUD_REPUTATION
    stage_id: ClassVar[str] = "reputation"
    requires_key: ClassVar[bool] = True
    supports_upload: ClassVar[bool] = False
    max_upload_bytes: ClassVar[int] = 0

    async def lookup_hash(self, sha256: str) -> list[Signal]:
        """A hash listed as an IOC with confidence >= 75 is a decisive detection."""
        response = await self._request(
            "POST",
            _API,
            headers={"Auth-Key": self._api_key or ""},
            data={"query": "search_hash", "hash": sha256},
        )
        if response is None:
            return []
        try:
            body = response.json()
        except ValueError as exc:
            log.warning("threatfox.parse_failed", error=str(exc))
            return []
        if body.get("query_status") != "ok":
            return []

        entries = body.get("data") or []
        if not isinstance(entries, list) or not entries:
            return []
        confidence = max((int(e.get("confidence_level", 0)) for e in entries), default=0)
        malware = str(entries[0].get("malware_printable") or "")
        decisive = confidence >= _CONFIDENCE_DECISIVE
        return [
            self._signal(
                severity=Severity.CRITICAL if decisive else Severity.MEDIUM,
                title_key="signal.threatfox.ioc",
                title_en=f"ThreatFox IOC: {malware} (confidence {confidence})",
                detail=f"{malware} confidence={confidence}",
                weight=weight("reputation", "threatfox_ioc", 85) if decisive else 30,
                decisive=decisive,
                data={"malware": malware, "confidence": confidence},
            )
        ]
