"""Stage-13 upload for VirusTotal, entirely via respx (never real network, §13).

Covers: small/large file paths, streaming (no full read), poll status handling, the
180 s cap, cancellation, 429 retry, missing/invalid key, and -- critically -- that
neither the API key nor the one-time upload URL ever reaches a log record.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from structlog.testing import capture_logs

import prescan.core.providers.virustotal as vt_mod
from prescan.core.models import Availability
from prescan.core.providers.virustotal import VirusTotalProvider
from prescan.core.ratelimit import RateLimiter

_KEY = "SECRET-VT-KEY-abcdef0123456789"
_ONE_TIME_URL = "https://upload.virustotal.test/ONE-TIME-SECRET-URL"
_FILES = "https://www.virustotal.com/api/v3/files"
_UPLOAD_URL = "https://www.virustotal.com/api/v3/files/upload_url"


async def _instant(_delay: float) -> None:
    """A sleep that never waits, so the rate limiter and retries stay real-time-free."""


def _provider(key: str | None = _KEY) -> VirusTotalProvider:
    return VirusTotalProvider(key, RateLimiter(sleep=_instant), allow_network=True)


def _analysis(status: str, *, malicious: int = 0, **stats: int) -> dict[str, Any]:
    base = {"malicious": malicious, "harmless": 70, "undetected": 0, "suspicious": 0}
    return {"data": {"attributes": {"status": status, "stats": {**base, **stats}}}}


def _analyses_route(analysis_id: str = "AID") -> str:
    return f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"


def _small_file(tmp_path: Path) -> Path:
    p = tmp_path / "sample.bin"
    p.write_bytes(b"hello world")
    return p


class _Now:
    """Monotonic-like fake: returns a preset sequence, then holds the last value."""

    def __init__(self, values: list[float]) -> None:
        self._values = values
        self._i = 0

    def __call__(self) -> float:
        v = self._values[min(self._i, len(self._values) - 1)]
        self._i += 1
        return v


@respx.mock
@pytest.mark.asyncio
async def test_small_file_direct_upload_completed(tmp_path: Path) -> None:
    respx.post(_FILES).mock(return_value=httpx.Response(200, json={"data": {"id": "AID"}}))
    respx.get(_analyses_route()).mock(return_value=httpx.Response(200, json=_analysis("completed")))

    outcome = await _provider().upload_file(_small_file(tmp_path), sleep=_instant)

    assert outcome.sent is True and outcome.sent_at is not None
    assert outcome.availability is Availability.READY
    assert outcome.signals and outcome.signals[0].data.get("authoritative_clean") is True


@respx.mock
@pytest.mark.asyncio
async def test_large_file_uses_one_time_upload_url_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(vt_mod, "_DIRECT_UPLOAD_MAX", 4)  # force the large-file branch
    respx.get(_UPLOAD_URL).mock(return_value=httpx.Response(200, json={"data": _ONE_TIME_URL}))
    one_time = respx.post(_ONE_TIME_URL).mock(
        return_value=httpx.Response(200, json={"data": {"id": "AID"}})
    )
    respx.get(_analyses_route()).mock(return_value=httpx.Response(200, json=_analysis("completed")))

    outcome = await _provider().upload_file(_small_file(tmp_path), sleep=_instant)

    assert outcome.sent is True and outcome.availability is Availability.READY
    assert one_time.call_count == 1  # the one-time URL is used exactly once, never reused


@respx.mock
@pytest.mark.asyncio
async def test_file_is_streamed_not_read_whole(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # If the upload path called path.read_bytes() it would load the file whole (a 650 MiB
    # file into RAM). Make read_bytes explode; a passing upload proves it streams.
    monkeypatch.setattr(
        Path, "read_bytes", lambda self: pytest.fail("file was read whole into memory")
    )
    respx.post(_FILES).mock(return_value=httpx.Response(200, json={"data": {"id": "AID"}}))
    respx.get(_analyses_route()).mock(return_value=httpx.Response(200, json=_analysis("completed")))

    outcome = await _provider().upload_file(_small_file(tmp_path), sleep=_instant)
    assert outcome.sent is True and outcome.availability is Availability.READY


@respx.mock
@pytest.mark.asyncio
async def test_poll_waits_through_non_completed_states(tmp_path: Path) -> None:
    respx.post(_FILES).mock(return_value=httpx.Response(200, json={"data": {"id": "AID"}}))
    respx.get(_analyses_route()).mock(
        side_effect=[
            httpx.Response(200, json=_analysis("queued")),
            httpx.Response(200, json=_analysis("in-progress")),
            httpx.Response(200, json=_analysis("completed", malicious=9)),
        ]
    )
    outcome = await _provider().upload_file(_small_file(tmp_path), sleep=_instant)

    # Only the completed poll scored: a decisive detection from 9 malicious.
    assert outcome.availability is Availability.READY
    assert len(outcome.signals) == 1 and outcome.signals[0].decisive is True


@respx.mock
@pytest.mark.asyncio
async def test_poll_timeout_is_error_but_file_stayed_sent(tmp_path: Path) -> None:
    respx.post(_FILES).mock(return_value=httpx.Response(200, json={"data": {"id": "AID"}}))
    respx.get(_analyses_route()).mock(
        return_value=httpx.Response(200, json=_analysis("in-progress"))
    )

    # now(): deadline base 0 -> cap 180; next reading 999 is already past it.
    outcome = await _provider().upload_file(
        _small_file(tmp_path), sleep=_instant, now=_Now([0.0, 999.0])
    )
    assert outcome.sent is True and outcome.sent_at is not None  # bytes left -> recorded (point 8)
    assert outcome.availability is Availability.ERROR
    assert "180 s" in outcome.detail


@respx.mock
@pytest.mark.asyncio
async def test_cancel_stops_waiting_but_file_already_left(tmp_path: Path) -> None:
    respx.post(_FILES).mock(return_value=httpx.Response(200, json={"data": {"id": "AID"}}))
    respx.get(_analyses_route()).mock(
        return_value=httpx.Response(200, json=_analysis("in-progress"))
    )
    cancel = asyncio.Event()
    cancel.set()  # cancel before the poll: the send happened, the wait must stop

    outcome = await _provider().upload_file(_small_file(tmp_path), cancel=cancel, sleep=_instant)
    assert outcome.sent is True  # the file already left; cancel does not recall it (point 10)
    assert outcome.availability is Availability.ERROR and "cancel" in outcome.detail.lower()


@respx.mock
@pytest.mark.asyncio
async def test_429_is_retried_not_crash(tmp_path: Path) -> None:
    post = respx.post(_FILES).mock(
        side_effect=[
            httpx.Response(429),
            httpx.Response(200, json={"data": {"id": "AID"}}),
        ]
    )
    respx.get(_analyses_route()).mock(return_value=httpx.Response(200, json=_analysis("completed")))

    outcome = await _provider().upload_file(_small_file(tmp_path), sleep=_instant)
    assert outcome.sent is True and outcome.availability is Availability.READY
    assert post.call_count == 2  # 429 then success, via tenacity retry


@pytest.mark.asyncio
async def test_missing_key_is_no_key(tmp_path: Path) -> None:
    outcome = await _provider(None).upload_file(_small_file(tmp_path), sleep=_instant)
    assert outcome.availability is Availability.NO_KEY and outcome.sent is False


@pytest.mark.asyncio
async def test_non_ascii_key_is_error_not_exception(tmp_path: Path) -> None:
    outcome = await _provider("\x80\x81bad").upload_file(_small_file(tmp_path), sleep=_instant)
    assert outcome.availability is Availability.ERROR and outcome.sent is False


@respx.mock
@pytest.mark.asyncio
async def test_no_key_or_upload_url_leaks_into_logs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(vt_mod, "_DIRECT_UPLOAD_MAX", 4)  # exercise the one-time URL branch
    respx.get(_UPLOAD_URL).mock(return_value=httpx.Response(200, json={"data": _ONE_TIME_URL}))
    file = _small_file(tmp_path)

    async def _run() -> None:
        # 1) success, 2) all-429 (send fails), 3) poll timeout, 4) transport error on send
        respx.post(_ONE_TIME_URL).mock(return_value=httpx.Response(200, json={"data": {"id": "A"}}))
        respx.get(_analyses_route("A")).mock(
            return_value=httpx.Response(200, json=_analysis("completed"))
        )
        await _provider().upload_file(file, sleep=_instant)

        respx.post(_ONE_TIME_URL).mock(return_value=httpx.Response(429))
        await _provider().upload_file(file, sleep=_instant)

        respx.post(_ONE_TIME_URL).mock(return_value=httpx.Response(200, json={"data": {"id": "B"}}))
        respx.get(_analyses_route("B")).mock(
            return_value=httpx.Response(200, json=_analysis("in-progress"))
        )
        await _provider().upload_file(file, sleep=_instant, now=_Now([0.0, 999.0]))

        respx.post(_ONE_TIME_URL).mock(side_effect=httpx.ConnectError("boom"))
        await _provider().upload_file(file, sleep=_instant)

    with capture_logs() as logs:
        await _run()

    blob = json.dumps(logs, default=str)
    assert _KEY not in blob, "API key leaked into a log record"
    assert _ONE_TIME_URL not in blob, "one-time upload URL leaked into a log record"
    assert "ONE-TIME-SECRET-URL" not in blob and "SECRET-VT-KEY" not in blob
