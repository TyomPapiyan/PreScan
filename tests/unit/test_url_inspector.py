"""Tests for core/url/inspector.py: redirect chain cap and metadata (respx)."""

from __future__ import annotations

import httpx
import pytest
import respx

from prescan.core.url.inspector import inspect


@respx.mock
@pytest.mark.asyncio
async def test_redirect_chain_stops_at_ten_hops() -> None:
    # 15 hops available; the inspector must stop after 10.
    for i in range(15):
        respx.head(f"https://hop{i}.test/").mock(
            return_value=httpx.Response(301, headers={"location": f"https://hop{i + 1}.test/"})
        )
    respx.head("https://hop15.test/").mock(return_value=httpx.Response(200))

    result = await inspect("https://hop0.test/", max_hops=10)
    assert result.hop_limit_hit is True
    assert len(result.redirect_chain) == 10


@respx.mock
@pytest.mark.asyncio
async def test_registrable_domain_change_detected() -> None:
    respx.head("https://good.com/").mock(
        return_value=httpx.Response(302, headers={"location": "https://evil.ru/"})
    )
    respx.head("https://evil.ru/").mock(
        return_value=httpx.Response(200, headers={"content-type": "application/octet-stream"})
    )
    result = await inspect("https://good.com/")
    assert result.registrable_changed is True
    assert result.final_url == "https://evil.ru/"
    assert result.content_type == "application/octet-stream"
