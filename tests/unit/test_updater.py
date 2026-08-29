"""Tests for core/updater.py. Network is mocked with respx (never real, §13)."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import httpx
import pytest
import respx

from prescan.core.errors import UpdateError
from prescan.core.updater import YARA_FORGE_FULL_URL, update_yara_rules


def _rules_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("packages/full/demo.yar", "rule demo { condition: true }")
        zf.writestr("README.md", "not a rule")
    return buffer.getvalue()


@respx.mock
@pytest.mark.asyncio
async def test_update_installs_rules(tmp_path: Path) -> None:
    respx.get(YARA_FORGE_FULL_URL).mock(return_value=httpx.Response(200, content=_rules_zip()))
    dest = tmp_path / "yara"
    installed = await update_yara_rules(dest, timeout_s=30)
    assert installed == 1
    assert (dest / "demo.yar").exists()


@respx.mock
@pytest.mark.asyncio
async def test_update_raises_on_http_error(tmp_path: Path) -> None:
    respx.get(YARA_FORGE_FULL_URL).mock(return_value=httpx.Response(500))
    with pytest.raises(UpdateError):
        await update_yara_rules(tmp_path / "yara", timeout_s=30)
