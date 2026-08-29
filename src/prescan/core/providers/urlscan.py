"""urlscan.io provider: reputation by searching existing scans (§7 stage 3).

Uses the search API (query by domain) rather than submitting a new scan, so we
read community results without publishing the URL ourselves.
"""

from __future__ import annotations

from typing import ClassVar
from urllib.parse import urlsplit

import structlog

from prescan.core.models import Severity, Signal, SourceKind
from prescan.core.providers.base import HttpProvider

log = structlog.get_logger(__name__)

_API = "https://urlscan.io/api/v1/search/"


class UrlscanProvider(HttpProvider):
    """urlscan.io reputation via a domain search."""

    name: ClassVar[str] = "urlscan"
    kind: ClassVar[SourceKind] = SourceKind.CLOUD_REPUTATION
    stage_id: ClassVar[str] = "url_reputation"
    requires_key: ClassVar[bool] = True
    supports_upload: ClassVar[bool] = False
    max_upload_bytes: ClassVar[int] = 0

    async def lookup_url(self, url: str) -> list[Signal]:
        """Search urlscan for prior scans of this domain; flag malicious ones."""
        host = (urlsplit(url if "://" in url else f"http://{url}").hostname or "").lower()
        if not host:
            return []
        response = await self._request(
            "GET",
            _API,
            headers={"API-Key": self._api_key or ""},
            params={"q": f"domain:{host}"},
        )
        if response is None:
            return []
        try:
            results = response.json().get("results") or []
        except ValueError as exc:
            log.warning("urlscan.parse_failed", error=str(exc))
            return []

        malicious = sum(1 for r in results if _is_malicious(r))
        if malicious == 0:
            return []
        return [
            self._signal(
                severity=Severity.MEDIUM,
                title_key="signal.urlscan.malicious",
                title_en=f"urlscan.io: {malicious} prior scan(s) flagged this domain",
                detail=f"{malicious} malicious result(s)",
                weight=25,
                data={"malicious": malicious, "host": host},
            )
        ]


def _is_malicious(result: dict[str, object]) -> bool:
    """True if a urlscan search result carries a malicious verdict."""
    verdicts = result.get("verdicts")
    if isinstance(verdicts, dict):
        overall = verdicts.get("overall")
        if isinstance(overall, dict):
            return bool(overall.get("malicious"))
    return False
