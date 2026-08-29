"""OPSWAT MetaDefender provider: reputation by file hash (hash only, §6.2)."""

from __future__ import annotations

from typing import ClassVar

import structlog

from prescan.core.models import Severity, Signal, SourceKind
from prescan.core.providers.base import HttpProvider
from prescan.core.scoring import weight

log = structlog.get_logger(__name__)

_API = "https://api.metadefender.com/v4/hash/{sha256}"
_CAP = 90


class MetaDefenderProvider(HttpProvider):
    """MetaDefender Cloud hash lookup by SHA-256."""

    name: ClassVar[str] = "metadefender"
    kind: ClassVar[SourceKind] = SourceKind.CLOUD_REPUTATION
    stage_id: ClassVar[str] = "reputation"
    requires_key: ClassVar[bool] = True
    supports_upload: ClassVar[bool] = True
    max_upload_bytes: ClassVar[int] = 140 * 1024 * 1024

    async def lookup_hash(self, sha256: str) -> list[Signal]:
        """Return reputation signals for a hash. Unknown hash -> no signal."""
        response = await self._request(
            "GET",
            _API.format(sha256=sha256),
            headers={"apikey": self._api_key or ""},
        )
        if response is None:  # 404: not in MetaDefender's database
            return []
        try:
            body = response.json()
            # A "not found" body carries error code 404003 rather than a 404 status.
            if "error" in body:
                return []
            scan = body["scan_results"]
            malicious = int(scan.get("total_detected_avs", 0))
            total = int(scan.get("total_avs", 0))
        except (ValueError, KeyError, TypeError) as exc:
            log.warning("metadefender.parse_failed", error=str(exc))
            return []

        per_hit = weight("reputation", "vt_malicious_per_hit", 22)
        if malicious >= 4:
            return [
                self._signal(
                    severity=Severity.CRITICAL,
                    title_key="signal.metadefender.detection",
                    title_en=f"MetaDefender: {malicious}/{total} engines flagged this file",
                    detail=f"{malicious}/{total}",
                    weight=min(_CAP, per_hit * malicious),
                    decisive=True,
                    data={"malicious": malicious, "total": total},
                )
            ]
        if malicious >= 1:
            return [
                self._signal(
                    severity=Severity.MEDIUM,
                    title_key="signal.metadefender.detection",
                    title_en=f"MetaDefender: {malicious}/{total} engines flagged this file",
                    detail=f"{malicious}/{total}",
                    weight=min(_CAP, per_hit * malicious),
                    data={"malicious": malicious, "total": total},
                )
            ]
        return [
            self._signal(
                severity=Severity.INFO,
                title_key="signal.metadefender.clean",
                title_en=f"MetaDefender: 0/{total} engines flagged this file",
                weight=weight("reputation", "vt_known_clean", -20),
                data={"malicious": 0, "total": total, "authoritative_clean": True},
            )
        ]
