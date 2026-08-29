"""Mandatory EICAR smoke test (spec §13.1).

If clamd is reachable the EICAR file must come back DANGEROUS end-to-end. If it
is not, the test skips with a clear reason — it is never silently passed. This
is the first test to check on a detection regression.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from prescan.core.config import AppConfig
from prescan.core.engines.clamav import ClamAVEngine
from prescan.core.models import ScanRequest, TargetKind, Verdict
from prescan.core.pipeline import Pipeline
from tests.fixtures.eicar import eicar_bytes


@pytest.mark.asyncio
async def test_eicar_is_dangerous_when_clamd_available(tmp_path: Path) -> None:
    config = AppConfig.load()
    availability, detail = await ClamAVEngine(config).availability()
    if availability.value != "ready":
        pytest.skip(f"clamd not available: {detail}")

    target = tmp_path / "eicar.com"
    target.write_bytes(eicar_bytes())

    request = ScanRequest(target_kind=TargetKind.FILE, file_path=target, allow_network=False)
    report = await Pipeline(config).run(request)

    assert report.verdict is Verdict.DANGEROUS
    assert report.risk_score >= 80
    assert any(s.source == "clamav" and s.decisive for s in report.signals)
