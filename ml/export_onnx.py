"""Convert the EMBER2024 LightGBM model to ONNX (M6a).

Uses ``onnxmltools.convert_lightgbm`` on the downloaded ``.model`` booster and
writes ``model.onnx`` into the PreScan user data dir (or ``--out``). The resulting
graph takes a float32 ``input`` of shape ``[None, 2568]`` and yields
``probabilities`` of shape ``[N, 2]`` as ``[P(benign), P(malicious)]``.

    python ml/export_onnx.py --model ml/models/EMBER2024_all.model

Runtime inference then needs only onnxruntime + numpy + pefile (spec §3.4).
"""

from __future__ import annotations

import argparse
from pathlib import Path


def convert(model_file: Path, out_path: Path, opset: int = 15) -> Path:
    """Convert a LightGBM booster file to ONNX at out_path."""
    import lightgbm as lgb
    from onnxmltools import convert_lightgbm
    from onnxmltools.convert.common.data_types import FloatTensorType

    booster = lgb.Booster(model_file=str(model_file))
    dim = booster.num_feature()
    onnx_model = convert_lightgbm(
        booster,
        initial_types=[("input", FloatTensorType([None, dim]))],
        zipmap=False,
        target_opset=opset,
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(onnx_model.SerializeToString())
    return out_path


def _default_out() -> Path:
    from prescan.core.config import Paths

    return Paths.resolve().model_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True, help="path to *.model booster")
    parser.add_argument("--out", type=Path, default=None, help="output model.onnx path")
    parser.add_argument("--opset", type=int, default=15)
    args = parser.parse_args()

    out = args.out or _default_out()
    path = convert(args.model, out, args.opset)
    print(f"wrote {path} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
