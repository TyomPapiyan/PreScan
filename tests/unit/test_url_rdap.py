"""Tests for core/url/rdap.py via respx (never real network, §13)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx

from prescan.core.url.rdap import domain_age_days


@respx.mock
@pytest.mark.asyncio
async def test_domain_age_from_registration_event() -> None:
    registered = (datetime.now(UTC) - timedelta(days=400)).isoformat()
    body = {"events": [{"eventAction": "registration", "eventDate": registered}]}
    respx.get(host="rdap.org").mock(return_value=httpx.Response(200, json=body))
    age = await domain_age_days("example.com")
    assert age is not None
    assert 395 <= age <= 405


@respx.mock
@pytest.mark.asyncio
async def test_young_domain_age() -> None:
    registered = (datetime.now(UTC) - timedelta(days=3)).isoformat()
    body = {"events": [{"eventAction": "registration", "eventDate": registered}]}
    respx.get(host="rdap.org").mock(return_value=httpx.Response(200, json=body))
    assert await domain_age_days("new.test") == 3


@respx.mock
@pytest.mark.asyncio
async def test_rdap_failure_returns_none() -> None:
    respx.get(host="rdap.org").mock(return_value=httpx.Response(404))
    assert await domain_age_days("missing.test") is None
