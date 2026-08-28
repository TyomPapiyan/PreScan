# PreScan ML (research)

Research and model-conversion code. **Not part of the shipped application** and
not type-checked as package code. The app only ever runs `onnxruntime` + `numpy`
+ `pefile` at inference time (spec §3.4).

- **M6a** (ships): convert the EMBER2024 benchmark LightGBM classifier to ONNX
  (`model.onnx`) and implement the EMBER feature-version-3 vector in
  `src/prescan/core/ml/features.py`. The feature vector must match `thrember`
  bit-for-bit — a blocking test.
- **M6b** (later, not in v1): train our own LightGBM on EMBER2024 with a **time
  split**, evaluate by **FPR @ TPR=0.99**, export to ONNX, add SHAP top factors.

## `thrember`

Not on PyPI. Install from git:

```bash
git clone https://github.com/FutureComputing4AI/EMBER2024.git
cd EMBER2024/ && pip install .
```

## Scripts

| Script | Purpose |
|---|---|
| `download_ember2024.py` | Download benchmark models / dataset via `thrember`. |
| `features.py` | Feature extraction for training. |
| `train_lightgbm.py` | Train the classifier (time split, Win32+Win64 subset). |
| `evaluate.py` | ROC AUC, FPR@TPR=0.99, per-type breakdown. |
| `export_onnx.py` | Export the trained model to ONNX. |
| `explain_shap.py` | SHAP top-3 factors. |
