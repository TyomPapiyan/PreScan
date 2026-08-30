"""VirusTotal provider: reputation by file hash (only the hash leaves, §6.2)."""

from __future__ import annotations

import base64
from typing import ClassVar

import structlog

from prescan.core.models import Severity, Signal, SourceKind
from prescan.core.providers.base import HttpProvider
from prescan.core.scoring import weight

log = structlog.get_logger(__name__)

_API = "https://www.virustotal.com/api/v3/files/{sha256}"
_URL_API = "https://www.virustotal.com/api/v3/urls/{url_id}"
_VT_CAP = 90  # §8.4: vt_malicious_per_hit multiplied by hits, capped at 90


class VirusTotalProvider(HttpProvider):
    """VirusTotal v3 file lookup by SHA-256."""

    name: ClassVar[str] = "virustotal"
    kind: ClassVar[SourceKind] = SourceKind.CLOUD_REPUTATION
    stage_id: ClassVar[str] = "reputation"
    requires_key: ClassVar[bool] = True
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
            malicious = int(stats.get("malicious", 0))
            total = sum(int(v) for v in stats.values())
        except (ValueError, KeyError, TypeError) as exc:
            log.warning("virustotal.parse_failed", error=str(exc))
            return []

        if malicious >= 4:
            return [self._detection(malicious, total, decisive=True, severity=Severity.CRITICAL)]
        if malicious >= 1:
            return [self._detection(malicious, total, decisive=False, severity=Severity.MEDIUM)]
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
        return []

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
