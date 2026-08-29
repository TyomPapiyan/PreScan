"""Tests for URL-reputation providers via respx (never real network, §13)."""

from __future__ import annotations

import base64
import hashlib

import httpx
import pytest
import respx

from prescan.core.models import Availability, Verdict
from prescan.core.providers.safebrowsing import SafeBrowsingProvider
from prescan.core.providers.urlhaus import UrlhausProvider
from prescan.core.providers.urlscan import UrlscanProvider
from prescan.core.ratelimit import RateLimiter
from prescan.core.scoring import score


def _limiter() -> RateLimiter:
    return RateLimiter()


# --- Safe Browsing: hash-prefix confirmation (never sends the URL) --------- #
@respx.mock
@pytest.mark.asyncio
async def test_safebrowsing_confirms_full_hash_threat() -> None:
    url = "https://malware.test/path"
    expr = "malware.test/"  # one of the generated expressions
    full = hashlib.sha256(expr.encode()).digest()
    full_b64 = base64.urlsafe_b64encode(full).decode().rstrip("=")
    body = {"fullHashes": [{"fullHash": full_b64, "fullHashDetails": [{"threatType": "MALWARE"}]}]}
    route = respx.get(host="safebrowsing.googleapis.com").mock(
        return_value=httpx.Response(200, json=body)
    )

    provider = SafeBrowsingProvider("key", _limiter(), allow_network=True)
    signals = await provider.lookup_url(url)

    # Privacy: the request carried only hash prefixes, never the URL/host.
    sent = route.calls.last.request
    assert "malware.test" not in str(sent.url)
    assert "hashPrefixes" in str(sent.url)
    assert signals and signals[0].decisive
    verdict, _r, _k, _rr = score(signals, had_authoritative_source=True)
    assert verdict is Verdict.DANGEROUS


@respx.mock
@pytest.mark.asyncio
async def test_safebrowsing_prefix_collision_ignored() -> None:
    other = base64.urlsafe_b64encode(hashlib.sha256(b"unrelated").digest()).decode().rstrip("=")
    body = {"fullHashes": [{"fullHash": other, "fullHashDetails": [{"threatType": "MALWARE"}]}]}
    respx.get(host="safebrowsing.googleapis.com").mock(return_value=httpx.Response(200, json=body))
    provider = SafeBrowsingProvider("key", _limiter(), allow_network=True)
    assert await provider.lookup_url("https://clean.test/") == []


# --- URLhaus -------------------------------------------------------------- #
@respx.mock
@pytest.mark.asyncio
async def test_urlhaus_online_is_decisive() -> None:
    body = {"query_status": "ok", "url_status": "online", "threat": "malware_download"}
    respx.post("https://urlhaus-api.abuse.ch/v1/url/").mock(
        return_value=httpx.Response(200, json=body)
    )
    signals = await UrlhausProvider("key", _limiter(), allow_network=True).lookup_url("http://x/y")
    assert signals[0].decisive is True
    verdict, _r, _k, _rr = score(signals, had_authoritative_source=True)
    assert verdict is Verdict.DANGEROUS


@respx.mock
@pytest.mark.asyncio
async def test_urlhaus_unknown_is_empty() -> None:
    respx.post("https://urlhaus-api.abuse.ch/v1/url/").mock(
        return_value=httpx.Response(200, json={"query_status": "no_results"})
    )
    assert await UrlhausProvider("k", _limiter(), allow_network=True).lookup_url("http://x") == []


# --- urlscan.io ----------------------------------------------------------- #
@respx.mock
@pytest.mark.asyncio
async def test_urlscan_flags_malicious_domain() -> None:
    body = {"results": [{"verdicts": {"overall": {"malicious": True}}}]}
    respx.get("https://urlscan.io/api/v1/search/").mock(return_value=httpx.Response(200, json=body))
    signals = await UrlscanProvider("key", _limiter(), allow_network=True).lookup_url(
        "https://bad.test/"
    )
    assert signals and signals[0].data["malicious"] == 1


@pytest.mark.asyncio
async def test_url_providers_no_key_is_no_key() -> None:
    for provider in (
        SafeBrowsingProvider(None, _limiter(), allow_network=True),
        UrlhausProvider(None, _limiter(), allow_network=True),
        UrlscanProvider(None, _limiter(), allow_network=True),
    ):
        availability, _detail = await provider.availability()
        assert availability is Availability.NO_KEY
