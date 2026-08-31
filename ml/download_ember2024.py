"""Download the EMBER2024 binary malicious/benign classifier (M6a).

Fetches the LightGBM ``EMBER2024_all.model`` (binary label, all file types) from
the Hugging Face benchmark-models repo. Not part of the shipped package: run once
in the dev environment, then convert with ``ml/export_onnx.py``.

    python ml/download_ember2024.py [--out-dir DIR] [--filename NAME]

Requires ``thrember`` (installed from the EMBER2024 git repo) and network access.
"""

from __future__ import annotations

import argparse
from pathlib import Path

REPO_ID = "joyce8/EMBER2024-benchmark-models"
DEFAULT_MODEL = "EMBER2024_all.model"


def download(out_dir: Path, filename: str = DEFAULT_MODEL) -> Path:
    """Download one benchmark model file and return its local path."""
    from huggingface_hub import hf_hub_download

    out_dir.mkdir(parents=True, exist_ok=True)
    path = hf_hub_download(repo_id=REPO_ID, filename=filename, local_dir=str(out_dir))
    return Path(path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=Path("ml/models"))
    parser.add_argument("--filename", default=DEFAULT_MODEL)
    args = parser.parse_args()

    path = download(args.out_dir, args.filename)
    print(f"downloaded {path} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
