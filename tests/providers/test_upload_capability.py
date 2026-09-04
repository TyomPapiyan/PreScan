"""A provider that advertises supports_upload must actually implement upload_file.

Declaring the capability while inheriting the base stub is a promise without delivery
(metadefender did exactly that). This structural guard fails the moment it recurs --
deterministic, no network.
"""

from __future__ import annotations

from prescan.core.providers.base import HttpProvider
from prescan.core.providers.malwarebazaar import MalwareBazaarProvider
from prescan.core.providers.metadefender import MetaDefenderProvider
from prescan.core.providers.safebrowsing import SafeBrowsingProvider
from prescan.core.providers.threatfox import ThreatFoxProvider
from prescan.core.providers.urlhaus import UrlhausProvider
from prescan.core.providers.urlscan import UrlscanProvider
from prescan.core.providers.virustotal import VirusTotalProvider

_ALL_PROVIDERS = (
    VirusTotalProvider,
    MetaDefenderProvider,
    MalwareBazaarProvider,
    ThreatFoxProvider,
    SafeBrowsingProvider,
    UrlscanProvider,
    UrlhausProvider,
)


def test_supports_upload_implies_overridden_upload_file() -> None:
    for provider in _ALL_PROVIDERS:
        if provider.supports_upload:
            assert provider.upload_file is not HttpProvider.upload_file, (
                f"{provider.__name__} sets supports_upload=True but inherits the base "
                "upload_file stub -- implement it or set supports_upload=False"
            )
