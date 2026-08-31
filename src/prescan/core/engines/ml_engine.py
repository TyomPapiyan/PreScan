"""EMBER2024 features + onnxruntime inference engine.

The engine stays ``NO_MODEL`` (skipped, like a missing ClamAV, §16.5) until a
``model.onnx`` is present in the user data dir. When available it extracts the
EMBER feature-version-3 vector (``core/ml/features.py``, pefile-based) and runs a
single ONNX inference to obtain the malicious probability. The probability rides
on ``data["probability"]``; the scoring rules (§8.2/§8.3) decide what it means --
the ML signal must never masquerade as an antivirus verdict.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Final

import structlog

from prescan.core.engines.base import ScanContext
from prescan.core.errors import EngineSkipped, ScanCancelled
from prescan.core.models import Availability, Severity, Signal, SourceKind

if TYPE_CHECKING:
    import onnxruntime as ort

log = structlog.get_logger(__name__)

#: Probability tiers for the signal severity the user sees. The verdict thresholds
#: themselves live in scoring.py (§8.2 escalation 0.70, §8.3 clearance 0.20).
_SUSPICIOUS_PROB = 0.70
_BENIGN_PROB = 0.20

#: After vectorizing feature extraction (~120 ms/MiB measured), 256 MiB extracts in
#: ~30 s worst case -- within the 300 s pipeline timeout, comparable to capa's budget,
#: and it covers essentially all downloaded installers (the main pre-execution threat).
#: Above this the ml stage is skipped like the ClamAV size limit (§16.9).
ML_MAX_BYTES: Final = 256 * 1024 * 1024


class MLEngine:
    """ONNX malware classifier. Inactive until a model.onnx is installed."""

    name: ClassVar[str] = "ml"
    kind: ClassVar[SourceKind] = SourceKind.ML
    stage_id: ClassVar[str] = "ml"

    def __init__(self, model_path: Path, threshold: float = 0.70) -> None:
        self._model_path = model_path
        self._threshold = threshold
        self._session: ort.InferenceSession | None = None
        self._input_name: str = "input"

    async def availability(self) -> tuple[Availability, str]:
        """NO_MODEL until model.onnx exists in the user data dir."""
        if not self._model_path.exists():
            return Availability.NO_MODEL, "model.onnx not installed"
        return Availability.READY, "model available"

    def _ensure_session(self) -> ort.InferenceSession:
        """Lazily build the ONNX session (CPU) and cache it."""
        if self._session is None:
            import onnxruntime as ort

            options = ort.SessionOptions()
            options.intra_op_num_threads = 1
            self._session = ort.InferenceSession(
                str(self._model_path),
                sess_options=options,
                providers=["CPUExecutionProvider"],
            )
            self._input_name = self._session.get_inputs()[0].name
        return self._session

    async def scan(self, ctx: ScanContext) -> list[Signal]:
        """Extract features and run inference. Never raises on bad input (§10.4)."""
        if ctx.info.size > ML_MAX_BYTES:
            raise EngineSkipped(
                Availability.TOO_LARGE,
                f"file is {ctx.info.size // (1024 * 1024)} MiB; exceeds the "
                f"{ML_MAX_BYTES // (1024 * 1024)} MiB ML limit (~130 ms/MiB to extract)",
            )
        try:
            return await asyncio.to_thread(self._infer, ctx)
        except ScanCancelled:
            raise  # cancellation is control flow, not a parse failure
        except Exception as exc:  # noqa: BLE001 - untrusted binary / model (§10.4)
            log.warning("ml.failed", error=str(exc))
            return [
                Signal(
                    source=self.name,
                    kind=self.kind,
                    severity=Severity.INFO,
                    title_key="signal.ml.error",
                    title_en="ML model could not score the file",
                    detail=str(exc),
                )
            ]

    def _infer(self, ctx: ScanContext) -> list[Signal]:
        """Synchronous feature extraction + ONNX inference (worker thread)."""
        from prescan.core.ml.features import PEFeatureExtractor

        data = ctx.path.read_bytes()
        vector = PEFeatureExtractor().feature_vector(data, ctx.cancel.is_set).reshape(1, -1)

        session = self._ensure_session()
        probability = self._run(session, vector)

        # Severity is what the user reads in the signal list, so it must reflect the
        # probability honestly (a 95% signal shown as INFO would be a lie). It does
        # NOT drive the verdict: scoring.py excludes source == "ml" from its
        # no-low-or-worse SAFE gate and decides ML purely from data["probability"]
        # (escalation §8.2 at 0.70, clearance §8.3 at 0.20 plus signature).
        if probability >= _SUSPICIOUS_PROB:
            severity = Severity.HIGH
        elif probability >= _BENIGN_PROB:
            severity = Severity.LOW
        else:
            severity = Severity.INFO

        return [
            Signal(
                source=self.name,
                kind=self.kind,
                severity=severity,
                title_key="signal.ml.assessment",
                title_en=f"ML model: {probability:.0%} likely malicious",
                detail=f"probability={probability:.4f}",
                weight=round(probability * 100),
                data={"probability": probability, "threshold": self._threshold},
            )
        ]

    def _run(self, session: ort.InferenceSession, vector: Any) -> float:
        """Run the session and return the malicious probability (class 1)."""
        outputs = session.run(None, {self._input_name: vector})
        proba = None
        for meta, value in zip(session.get_outputs(), outputs, strict=True):
            if meta.name == "probabilities":
                proba = value
                break
        if proba is None:  # fall back to the last output
            proba = outputs[-1]
        # proba is shape [1, 2] as [P(benign), P(malicious)].
        return float(proba[0][1])
