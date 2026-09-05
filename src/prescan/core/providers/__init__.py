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
from prescan.core.providers.safebrowsing import SafeBrowsingProvider
from prescan.core.providers.threatfox import ThreatFoxProvider
from prescan.core.providers.urlhaus import UrlhausProvider
from prescan.core.providers.urlscan import UrlscanProvider
from prescan.core.providers.virustotal import VirusTotalProvider

if TYPE_CHECKING:
    from prescan.core.ratelimit import RateLimiter

__all__ = [
    "HttpProvider",
    "MalwareBazaarProvider",
    "MetaDefenderProvider",
    "Provider",
    "SafeBrowsingProvider",
    "ThreatFoxProvider",
    "UrlhausProvider",
    "UrlscanProvider",
    "VirusTotalProvider",
    "build_hash_providers",
    "build_upload_provider",
    "build_url_providers",
    "upload_provider_name",
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


def build_url_providers(
    limiter: RateLimiter,
    *,
    allow_network: bool = True,
) -> list[Provider]:
    """Return the URL-reputation providers (§7 stage 3), keyed from the keyring.

    Safe Browsing uses the hash-prefix API (never the full URL, §6.2).
    """
    from prescan.core.config import get_api_key

    abuse_key = get_api_key("malwarebazaar")
    return [
        SafeBrowsingProvider(get_api_key("safebrowsing"), limiter, allow_network=allow_network),
        UrlscanProvider(get_api_key("urlscan"), limiter, allow_network=allow_network),
        UrlhausProvider(abuse_key, limiter, allow_network=allow_network),
        VirusTotalProvider(get_api_key("virustotal"), limiter, allow_network=allow_network),
    ]


def _upload_provider_cls() -> type[VirusTotalProvider]:
    """The single choice of stage-13 upload provider (§6.2). VirusTotal for M8.

    Both ``build_upload_provider`` and ``upload_provider_name`` read the provider
    identity from here, so no caller ever hardcodes a provider name of its own.
    """
    return VirusTotalProvider


def build_upload_provider(limiter: RateLimiter, *, allow_network: bool = True) -> Provider:
    """Return the stage-13 upload provider. VirusTotal only in this version (M8)."""
    from prescan.core.config import get_api_key

    cls = _upload_provider_cls()
    return cls(get_api_key(cls.name), limiter, allow_network=allow_network)


def upload_provider_name() -> str:
    """Id of the configured stage-13 upload provider, from the same source as the builder.

    Reads only the class attribute -- no keyring, no network -- so it is safe to call
    just to name the service in a notification or a consent dialog (§10.5).
    """
    return _upload_provider_cls().name
