"""Domain age via RDAP (§7 stage 4).

A domain younger than 30 days is a strong risk signal (§8.2). Any lookup failure
degrades to ``None`` (age unknown) rather than raising.
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import structlog

log = structlog.get_logger(__name__)

_RDAP_BOOTSTRAP = "https://rdap.org/domain/{domain}"


async def domain_age_days(domain: str, *, timeout_s: float = 15.0) -> int | None:
    """Return the domain's age in days from its RDAP registration event, or None."""
    if not domain:
        return None
    url = _RDAP_BOOTSTRAP.format(domain=domain)
    try:
        timeout = httpx.Timeout(timeout_s, connect=15.0)
        async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client:
            response = await client.get(url, headers={"Accept": "application/rdap+json"})
        if response.status_code != httpx.codes.OK:
            return None
        registered = _registration_date(response.json())
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
        log.debug("rdap.lookup_failed", domain=domain, error=str(exc))
        return None
    if registered is None:
        return None
    return max(0, (datetime.now(UTC) - registered).days)


def _registration_date(body: dict[str, object]) -> datetime | None:
    """Extract the registration event date from an RDAP response."""
    events = body.get("events")
    if not isinstance(events, list):
        return None
    for event in events:
        if not isinstance(event, dict):
            continue
        if event.get("eventAction") == "registration":
            raw = event.get("eventDate")
            if isinstance(raw, str):
                return _parse_date(raw)
    return None


def _parse_date(raw: str) -> datetime | None:
    """Parse an RDAP ISO-8601 date into an aware UTC datetime."""
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
