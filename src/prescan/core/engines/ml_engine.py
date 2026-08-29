"""EMBER features + onnxruntime inference engine.

On M1 the model is absent, so the engine reports ``NO_MODEL`` and is skipped,
exactly like a missing ClamAV (spec §16.5). The feature vector and inference
land on M6a; the ML signal must never masquerade as an antivirus verdict.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

import structlog

from prescan.core.engines.base import ScanContext
from prescan.core.models import Availability, Signal, SourceKind

log = structlog.get_logger(__name__)


class MLEngine:
    """ONNX malware classifier. Inactive until a model.onnx is installed."""

    name: ClassVar[str] = "ml"
    kind: ClassVar[SourceKind] = SourceKind.ML
    stage_id: ClassVar[str] = "ml"

    def __init__(self, model_path: Path, threshold: float = 0.70) -> None:
        self._model_path = model_path
        self._threshold = threshold

    async def availability(self) -> tuple[Availability, str]:
        """NO_MODEL until model.onnx exists in the user data dir."""
        if not self._model_path.exists():
            return Availability.NO_MODEL, "model.onnx not installed"
        return Availability.READY, "model available"

    async def scan(self, ctx: ScanContext) -> list[Signal]:
        """Inference lands on M6a; nothing to contribute yet."""
        return []
