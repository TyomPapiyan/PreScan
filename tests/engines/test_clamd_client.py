"""Tests for core/engines/clamd_client.py.

Reply parsing is tested offline. A live INSTREAM smoke test runs only when the
clamd unix socket is present (never a hard network dependency).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from prescan.core.engines.clamd_client import ClamdClient
from prescan.core.errors import ClamdProtocolError
from tests.fixtures.eicar import eicar_bytes

_SOCKET = "/var/run/clamav/clamd.ctl"


def test_parse_clean_reply() -> None:
    result = ClamdClient._parse_scan_reply("stream: OK")
    assert result.status == "OK"
    assert not result.is_infected


def test_parse_found_reply() -> None:
    result = ClamdClient._parse_scan_reply("stream: Eicar-Test-Signature FOUND")
    assert result.is_infected
    assert result.signature == "Eicar-Test-Signature"


def test_parse_error_reply() -> None:
    result = ClamdClient._parse_scan_reply("stream: INSTREAM size limit exceeded ERROR")
    assert result.status == "ERROR"


def test_parse_rejects_garbage() -> None:
    with pytest.raises(ClamdProtocolError):
        ClamdClient._parse_scan_reply("nonsense")


def test_client_requires_a_target() -> None:
    with pytest.raises(ValueError, match="unix socket or a host"):
        ClamdClient()


@pytest.mark.skipif(not Path(_SOCKET).exists(), reason="clamd socket not present")
@pytest.mark.asyncio
async def test_live_eicar_detection(tmp_path: Path) -> None:
    client = ClamdClient(socket=_SOCKET, timeout_s=30)
    if not await client.ping():
        pytest.skip("clamd not responding")
    target = tmp_path / "eicar.com"
    target.write_bytes(eicar_bytes())
    result = await client.instream_file(target)
    assert result.is_infected


@pytest.mark.asyncio
async def test_missing_socket_reports_unavailable() -> None:
    client = ClamdClient(socket="/nonexistent/clamd.ctl", timeout_s=2)
    assert await client.ping() is False
    # A cancelled/absent daemon must not hang forever.
    await asyncio.wait_for(client.ping(), timeout=5)
