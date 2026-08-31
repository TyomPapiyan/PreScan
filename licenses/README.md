# Third-party licenses

This folder collects the licenses and notices of components PreScan depends on
or ships alongside (spec §11). On M7 the whole folder is placed next to the
executable in the distribution. The table is maintained by hand and updated
whenever a dependency is added.

| Component | License | File | Source |
|---|---|---|---|
| PySide6 / Qt | LGPLv3 | `LGPLv3.txt`, `GPLv3.txt` | https://download.qt.io/official_releases/QtForPython/ |
| RinUI | MIT | `MIT-RinUI.txt` | https://github.com/RinLit-233-shiroko/Rin-UI |
| YARA-X | BSD-3 | `BSD3-yara-x.txt` | https://github.com/VirusTotal/yara-x |
| LIEF | Apache-2.0 | `Apache2-LIEF.txt`, `NOTICE-LIEF` | https://github.com/lief-project/LIEF |
| capa | Apache-2.0 | `Apache2-capa.txt`, `NOTICE-capa` | https://github.com/mandiant/capa |
| ClamAV | GPL-2.0 | (not bundled) | https://www.clamav.net/ |
| oletools | BSD-2 / MIT | (to add) | https://github.com/decalage2/oletools |
| pikepdf | MPL-2.0 | (to add) | https://github.com/pikepdf/pikepdf |
| py7zr | LGPL-2.1+ | (to add) | https://github.com/miurahr/py7zr |
| YARA Forge | mixed permissive | (downloaded by user) | https://yaraforge.io/ |
| Microsoft Defender CLI | Windows EULA | (not distributed) | — |
| EMBER2024 benchmark model | Apache-2.0 | `Apache2-EMBER2024.txt` | https://huggingface.co/joyce8/EMBER2024-benchmark-models |
| EMBER2024 / thrember (feature code) | Apache-2.0 | `Apache2-EMBER2024.txt` | https://github.com/FutureComputing4AI/EMBER2024 |

## Notes

- **ClamAV** is never linked (`libclamav`); it is called as the external
  `clamd` process. Binaries are not embedded in the installer (spec §10.2, §11.2).
- **capa** is called as an external process (`capa --json`), not linked.
- **EMBER2024**: the shipped `model.onnx` is converted from the Apache-2.0
  `EMBER2024_all` LightGBM benchmark model. The feature extractor in
  `core/ml/features.py` and `core/ml/pefile_warnings.txt` are a derivative of the
  Apache-2.0 `thrember` package (EMBER2024). `model.onnx` itself is downloaded by
  the user / build step, never committed to the repo (spec §11.2).
- Full license texts are placeholders on M0 and are completed before the M7
  release build.
