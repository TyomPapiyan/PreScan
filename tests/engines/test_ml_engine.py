"""core/engines/ml_engine.py: availability, inference plumbing, signal mapping.

The real model.onnx is never in the repo (spec §11.2), so the ONNX session is
faked here: these tests exercise the engine's wiring (probability parsing,
severity/weight mapping, §10.4 robustness) without a model file.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from prescan.core.engines.base import ScanContext
from prescan.core.engines.ml_engine import ML_MAX_BYTES, MLEngine
from prescan.core.errors import EngineSkipped
from prescan.core.models import Availability, FileInfo, Severity


def _ctx(path: Path, workdir: Path, *, size: int | None = None) -> ScanContext:
    info = FileInfo(
        path=path,
        name=path.name,
        size=path.stat().st_size if size is None else size,
        declared_extension=path.suffix,
        detected_type="data",
        detected_mime="application/octet-stream",
        md5="0" * 32,
        sha1="0" * 40,
        sha256="0" * 64,
    )
    return ScanContext(path=path, info=info, cancel=asyncio.Event(), timeout_s=30, workdir=workdir)


class _FakeSession:
    """Stand-in for onnxruntime.InferenceSession returning a fixed probability."""

    def __init__(self, malicious: float) -> None:
        self._malicious = malicious

    def get_inputs(self) -> list[Any]:
        return [type("I", (), {"name": "input"})()]

    def get_outputs(self) -> list[Any]:
        return [type("O", (), {"name": n})() for n in ("label", "probabilities")]

    def run(self, _outputs: Any, _feeds: Any) -> list[Any]:
        proba = np.array([[1.0 - self._malicious, self._malicious]], dtype=np.float32)
        return [np.array([0]), proba]


@pytest.mark.asyncio
async def test_availability_no_model(tmp_path: Path) -> None:
    availability, _ = await MLEngine(tmp_path / "model.onnx").availability()
    assert availability is Availability.NO_MODEL


@pytest.mark.asyncio
async def test_availability_ready_when_model_present(tmp_path: Path) -> None:
    model = tmp_path / "model.onnx"
    model.write_bytes(b"not a real model")
    availability, _ = await MLEngine(model).availability()
    assert availability is Availability.READY


def test_run_extracts_class1_probability(tmp_path: Path) -> None:
    engine = MLEngine(tmp_path / "model.onnx")
    prob = engine._run(_FakeSession(0.83), np.zeros((1, 2568), dtype=np.float32))
    assert abs(prob - 0.83) < 1e-6


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("malicious", "severity"),
    [(0.07, Severity.INFO), (0.45, Severity.LOW), (0.90, Severity.HIGH)],
)
async def test_infer_signal_mapping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, malicious: float, severity: Severity
) -> None:
    target = tmp_path / "sample.bin"
    target.write_bytes(b"hello world, some content here " * 8)
    engine = MLEngine(tmp_path / "model.onnx")
    monkeypatch.setattr(engine, "_ensure_session", lambda: _FakeSession(malicious))

    signals = await engine.scan(_ctx(target, tmp_path))

    assert len(signals) == 1
    signal = signals[0]
    assert signal.source == "ml"
    # Severity is an honest tier the user sees; it does NOT gate SAFE (scoring
    # excludes source == "ml" from no_low_or_worse and uses data["probability"]).
    assert signal.severity is severity
    assert signal.weight == round(malicious * 100)
    assert abs(signal.data["probability"] - malicious) < 1e-6


@pytest.mark.asyncio
async def test_scan_skips_oversized_file(tmp_path: Path) -> None:
    """Above the size cap the stage is SKIPPED with a clear reason (§16.9 precedent)."""
    target = tmp_path / "big.bin"
    target.write_bytes(b"x")  # real bytes tiny; size is faked in the context
    engine = MLEngine(tmp_path / "model.onnx")
    with pytest.raises(EngineSkipped) as excinfo:
        await engine.scan(_ctx(target, tmp_path, size=ML_MAX_BYTES + 1))
    assert "ML limit" in excinfo.value.summary
    # Same class of situation as the ClamAV size limit -> the same availability.
    assert excinfo.value.availability is Availability.TOO_LARGE


@pytest.mark.asyncio
async def test_extraction_is_cancellable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A set cancel event aborts feature extraction with ScanCancelled, not a signal."""
    from prescan.core.errors import ScanCancelled

    target = tmp_path / "big.bin"
    target.write_bytes(b"MZ" + b"\x00" * 4_000_000)  # large enough to be worth aborting
    engine = MLEngine(tmp_path / "model.onnx")
    # The session must never be built: extraction should abort before inference.
    monkeypatch.setattr(
        engine, "_ensure_session", lambda: pytest.fail("inference ran despite cancel")
    )
    ctx = _ctx(target, tmp_path)
    ctx.cancel.set()

    with pytest.raises(ScanCancelled):
        await engine.scan(ctx)


@pytest.mark.asyncio
async def test_scan_never_raises_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A model/feature error yields one INFO signal, never an exception (§10.4)."""
    target = tmp_path / "sample.bin"
    target.write_bytes(b"content")
    engine = MLEngine(tmp_path / "model.onnx")

    def _boom() -> Any:
        raise RuntimeError("model load failed")

    monkeypatch.setattr(engine, "_ensure_session", _boom)
    signals = await engine.scan(_ctx(target, tmp_path))
    assert len(signals) == 1
    assert signals[0].severity is Severity.INFO
