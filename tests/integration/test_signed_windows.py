"""Windows-only checks on a real signed system binary (notepad.exe).

Two independent things, neither reachable on the Linux dev/CI host:

* the Microsoft Defender engine actually runs via ``MpCmdRun.exe`` -- a code path
  that never executes elsewhere in the project;
* a clean, Microsoft-signed binary clears to SAFE. This must be proven with the
  model **active** (ml stage READY): without a model ``ml_prob`` is ``None`` and
  SAFE would come from the old ``(ml_prob is None and trusted)`` branch, proving
  nothing about the §16.12 compensation. The compensation with a real probability
  above 0.20 is tested deterministically in ``tests/unit/test_scoring.py``
  (``test_trusted_signature_clears_biased_ml_probability``).

If Defender or the model is unavailable on the runner the relevant test skips with
an explicit reason -- a flaky/green-by-accident test is worse than a skipped one.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows-only signed-binary path")

_NOTEPAD = Path(r"C:\Windows\System32\notepad.exe")


async def _scan_notepad() -> object:
    if not _NOTEPAD.exists():
        pytest.skip("notepad.exe not present on this runner")
    from prescan.core.config import AppConfig
    from prescan.core.models import ScanRequest, TargetKind
    from prescan.core.pipeline import Pipeline

    request = ScanRequest(
        target_kind=TargetKind.FILE, file_path=_NOTEPAD, allow_network=False, force_refresh=True
    )
    return await Pipeline(AppConfig.load()).run(request)


def _stage(report: object, stage_id: str) -> object:
    return next((s for s in report.stages if s.stage_id == stage_id), None)  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_defender_engine_actually_runs() -> None:
    """Defender must reach READY and DONE via MpCmdRun.exe (its only exercise)."""
    from prescan.core.models import Availability, StageStatus

    report = await _scan_notepad()
    defender = _stage(report, "defender")
    assert defender is not None
    if defender.availability is not Availability.READY:  # type: ignore[attr-defined]
        pytest.skip(f"Defender not available on this runner: {defender.summary}")  # type: ignore[attr-defined]
    assert defender.status is StageStatus.DONE  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_signed_binary_clears_to_safe_with_model() -> None:
    """A clean signed PE clears to SAFE -- proven only with the ml stage READY."""
    from prescan.core.models import Availability, Verdict

    report = await _scan_notepad()
    ml = _stage(report, "ml")
    if ml is None or ml.availability is not Availability.READY:  # type: ignore[attr-defined]
        pytest.skip("model.onnx not installed — §16.12 SAFE-clearance path not exercised")

    # With the model active, ml_prob is a real number; a clean signed binary must
    # still clear (via ml_prob < 0.20 or the trusted-signature compensation §8.3),
    # never read as SUSPICIOUS/DANGEROUS (CLAUDE.md: a false positive on a clean
    # file costs more than a miss).
    assert report.verdict is Verdict.SAFE, (  # type: ignore[attr-defined]
        f"got {report.verdict}: {report.verdict_reason_en}"  # type: ignore[attr-defined]
    )
