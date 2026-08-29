"""Google Safe Browsing provider (URL reputation) via the hash-prefix API.

PRIVACY (§6.2): the full URL is **never** sent to Google. We canonicalise the
URL into expressions, SHA-256 each, and send only their 4-byte hash *prefixes*
to the v5 ``hashes:search`` endpoint; returned full hashes are confirmed locally.
This is the deliberate alternative to the Lookup API, which would send the URL.
Keyring id ``safebrowsing``. Free tier is non-commercial only.
"""

from __future__ import annotations

import base64
import hashlib
from typing import ClassVar
from urllib.parse import urlsplit

import httpx
import structlog

from prescan.core.models import Severity, Signal, SourceKind
from prescan.core.providers.base import HttpProvider
from prescan.core.scoring import weight

log = structlog.get_logger(__name__)

_API = "https://safebrowsing.googleapis.com/v5/hashes:search"
_DANGEROUS_THREATS = frozenset({"MALWARE", "SOCIAL_ENGINEERING"})


def _expressions(url: str) -> list[str]:
    """Return Safe Browsing URL expressions to hash (host + host/path)."""
    parts = urlsplit(url if "://" in url else f"http://{url}")
    host = (parts.hostname or "").lower()
    if not host:
        return []
    path = parts.path or "/"
    exprs = {f"{host}/", f"{host}{path}"}
    return sorted(exprs)


def _prefix(expression: str) -> tuple[bytes, str]:
    """Return (full sha256 digest, base64url 4-byte prefix) for an expression."""
    digest = hashlib.sha256(expression.encode("utf-8")).digest()
    prefix_b64 = base64.urlsafe_b64encode(digest[:4]).decode("ascii").rstrip("=")
    return digest, prefix_b64


class SafeBrowsingProvider(HttpProvider):
    """Google Safe Browsing URL check using hash prefixes only (never the URL)."""

    name: ClassVar[str] = "safebrowsing"
    kind: ClassVar[SourceKind] = SourceKind.CLOUD_REPUTATION
    stage_id: ClassVar[str] = "url_reputation"
    requires_key: ClassVar[bool] = True
    supports_upload: ClassVar[bool] = False
    max_upload_bytes: ClassVar[int] = 0

    async def lookup_url(self, url: str) -> list[Signal]:
        """Return a decisive DANGEROUS signal if a full hash confirms a threat."""
        expressions = _expressions(url)
        if not expressions:
            return []
        our_hashes = {expr: _prefix(expr) for expr in expressions}
        prefixes = [prefix for _digest, prefix in our_hashes.values()]

        response = await self._request(
            "GET",
            _API,
            params={"key": self._api_key or "", "hashPrefixes": prefixes},
        )
        if response is None:
            return []
        threats = self._confirm(response, {digest for digest, _p in our_hashes.values()})
        if not threats:
            return []
        return [
            self._signal(
                severity=Severity.CRITICAL,
                title_key="signal.safebrowsing.threat",
                title_en=f"Google Safe Browsing: {', '.join(sorted(threats))}",
                detail=", ".join(sorted(threats)),
                weight=weight("reputation", "safebrowsing_malware", 100),
                decisive=True,
                data={"threats": sorted(threats)},
            )
        ]

    def _confirm(self, response: httpx.Response, our_digests: set[bytes]) -> set[str]:
        """Confirm returned full hashes against ours; collect dangerous threats."""
        threats: set[str] = set()
        try:
            body = response.json()
        except ValueError:
            return threats
        for entry in body.get("fullHashes", []) or []:
            full_b64 = entry.get("fullHash")
            if not isinstance(full_b64, str):
                continue
            try:
                full = base64.urlsafe_b64decode(full_b64 + "==")
            except (ValueError, TypeError):
                continue
            if full not in our_digests:
                continue  # prefix collision, not our URL
            for detail in entry.get("fullHashDetails", []) or []:
                threat = detail.get("threatType")
                if threat in _DANGEROUS_THREATS:
                    threats.add(str(threat))
        return threats
