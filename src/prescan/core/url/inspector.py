"""Redirect chain and HEAD metadata (§7 stages 6-7).

Follows the redirect chain manually, capped at 10 hops, exposing the final URL
and whether the registrable domain changed along the way. Then reads response
metadata (Content-Type/Length/Disposition). Never raises: failures return a
partial result.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx
import structlog

from prescan.core.url.normalize import normalize

log = structlog.get_logger(__name__)

MAX_HOPS = 10
_FILENAME_RE = re.compile(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', re.IGNORECASE)


@dataclass
class InspectResult:
    """Redirect chain and response metadata for a URL."""

    final_url: str | None = None
    redirect_chain: list[str] = field(default_factory=list)
    registrable_changed: bool = False
    hop_limit_hit: bool = False
    http_status: int | None = None
    content_type: str | None = None
    content_length: int | None = None
    content_disposition_filename: str | None = None
    error: str | None = None


async def inspect(
    url: str,
    *,
    follow_redirects: bool = True,
    max_hops: int = MAX_HOPS,
    timeout_s: float = 30.0,
) -> InspectResult:
    """Walk the redirect chain (<= max_hops) and read final HEAD metadata."""
    result = InspectResult(final_url=url)
    timeout = httpx.Timeout(timeout_s, connect=15.0)
    start_reg = normalize(url).registrable_domain
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
            current = url
            for _hop in range(max_hops + 1):
                response = await _head_or_get(client, current)
                result.http_status = response.status_code
                if follow_redirects and response.is_redirect and "location" in response.headers:
                    nxt = str(response.next_request.url) if response.next_request else None
                    nxt = nxt or str(httpx.URL(current).join(response.headers["location"]))
                    result.redirect_chain.append(nxt)
                    current = nxt
                    if len(result.redirect_chain) >= max_hops:
                        result.hop_limit_hit = True
                        break
                    continue
                _read_metadata(response, result)
                break
            result.final_url = current
    except httpx.HTTPError as exc:
        log.debug("inspect.failed", url=url, error=str(exc))
        result.error = str(exc)

    final_reg = normalize(result.final_url or url).registrable_domain
    result.registrable_changed = bool(start_reg and final_reg and start_reg != final_reg)
    return result


async def _head_or_get(client: httpx.AsyncClient, url: str) -> httpx.Response:
    """HEAD the URL, falling back to a streamed GET if HEAD is unsupported."""
    response = await client.head(url)
    if response.status_code in (httpx.codes.METHOD_NOT_ALLOWED, httpx.codes.NOT_IMPLEMENTED):
        async with client.stream("GET", url) as streamed:
            return streamed
    return response


def _read_metadata(response: httpx.Response, result: InspectResult) -> None:
    """Fill Content-Type/Length/Disposition from response headers."""
    headers = response.headers
    result.content_type = headers.get("content-type")
    length = headers.get("content-length")
    result.content_length = int(length) if length and length.isdigit() else None
    disposition = headers.get("content-disposition")
    if disposition:
        match = _FILENAME_RE.search(disposition)
        if match:
            result.content_disposition_filename = match.group(1).strip()
