"""Cloud reputation and scan providers.

``build_hash_providers`` wires the stage-11 hash-reputation providers (§6): only
a SHA-256 leaves the machine here (§6.2). abuse.ch services (MalwareBazaar,
ThreatFox) share one account-wide Auth-Key, stored under the ``malwarebazaar``
keyring id.

URL providers (Safe Browsing, urlscan, URLhaus) belong to the §7 URL pipeline
and are wired on M3.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from prescan.core.providers.base import HttpProvider, Provider
from prescan.core.providers.malwarebazaar import MalwareBazaarProvider
from prescan.core.providers.metadefender import MetaDefenderProvider
from prescan.core.providers.threatfox import ThreatFoxProvider
from prescan.core.providers.virustotal import VirusTotalProvider

if TYPE_CHECKING:
    from prescan.core.ratelimit import RateLimiter

__all__ = [
    "HttpProvider",
    "MalwareBazaarProvider",
    "MetaDefenderProvider",
    "Provider",
    "ThreatFoxProvider",
    "VirusTotalProvider",
    "build_hash_providers",
]


def build_hash_providers(
    limiter: RateLimiter,
    *,
    allow_network: bool = True,
) -> list[Provider]:
    """Return the stage-11 hash-reputation providers, keyed from the keyring."""
    from prescan.core.config import get_api_key

    abuse_key = get_api_key("malwarebazaar")  # abuse.ch account-wide key
    return [
        VirusTotalProvider(get_api_key("virustotal"), limiter, allow_network=allow_network),
        MetaDefenderProvider(get_api_key("metadefender"), limiter, allow_network=allow_network),
        MalwareBazaarProvider(abuse_key, limiter, allow_network=allow_network),
        ThreatFoxProvider(abuse_key, limiter, allow_network=allow_network),
    ]
