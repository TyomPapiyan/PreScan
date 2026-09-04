"""The shared VirusTotal stats->signals path: honest denominator, unanalyzable files,
and byte-for-byte identity between the hash and upload routes (respx, no network)."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from prescan.core.providers.virustotal import VirusTotalProvider
from prescan.core.ratelimit import RateLimiter

_SHA = "a" * 64


async def _instant(_delay: float) -> None:
    """Non-waiting sleep so the shared limiter never spends real time."""


def _provider() -> VirusTotalProvider:
    return VirusTotalProvider("k", RateLimiter(sleep=_instant), allow_network=True)


def test_total_excludes_non_verdict_keys() -> None:
    """failure / timeout / confirmed-timeout / type-unsupported are not in the total."""
    clean = {"malicious": 0, "suspicious": 0, "harmless": 5, "undetected": 5}
    noisy = {**clean, "failure": 3, "timeout": 2, "confirmed-timeout": 1, "type-unsupported": 4}

    a = _provider()._file_signals_from_stats(clean)
    b = _provider()._file_signals_from_stats(noisy)
    assert a[0].data["total"] == 10  # 5 + 5, not 10 + 10 noise engines
    assert b[0].data["total"] == 10
    assert a[0].title_en == b[0].title_en == "VirusTotal: 0/10 engines flagged this file"


def test_unanalyzable_file_is_not_clean() -> None:
    """No engine rendered a verdict (only type-unsupported) -> INFO, never a green tick."""
    stats: dict[str, Any] = {
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "type-unsupported": 3,
    }
    signals = _provider()._file_signals_from_stats(stats)
    assert len(signals) == 1
    assert signals[0].title_key == "signal.vt.unanalyzable"
    assert "authoritative_clean" not in signals[0].data


@respx.mock
@pytest.mark.asyncio
async def test_hash_and_upload_paths_give_identical_signals() -> None:
    """The proof of the single path: the same stats via lookup_hash and upload_file
    produce byte-for-byte identical signals (and therefore identical verdicts)."""
    stats = {"malicious": 2, "suspicious": 0, "harmless": 60, "undetected": 8, "timeout": 3}
    analysis = {"data": {"attributes": {"status": "completed", "stats": stats}}}
    report = {"data": {"attributes": {"last_analysis_stats": stats}}}

    respx.get(f"https://www.virustotal.com/api/v3/files/{_SHA}").mock(
        return_value=httpx.Response(200, json=report)
    )
    respx.post("https://www.virustotal.com/api/v3/files").mock(
        return_value=httpx.Response(200, json={"data": {"id": "AID"}})
    )
    respx.get("https://www.virustotal.com/api/v3/analyses/AID").mock(
        return_value=httpx.Response(200, json=analysis)
    )

    tmp = Path(tempfile.mkdtemp()) / "f.bin"
    tmp.write_bytes(b"data")

    hash_signals = await _provider().lookup_hash(_SHA)
    upload = await _provider().upload_file(tmp, sleep=_instant)

    assert [s.model_dump() for s in hash_signals] == [s.model_dump() for s in upload.signals]
