"""--allow-upload is accepted (so scripts don't break) but inert: stage 13 does not
exist, so it must warn rather than silently no-op, and must not crash the scan.

Hermetic: a tiny local file with --no-network -- no cloud calls at all.
"""

from __future__ import annotations

import contextlib
from pathlib import Path

from typer.testing import CliRunner

from prescan.cli import app

_WARNING = "cloud file upload is not implemented"


def test_allow_upload_warns_and_does_not_crash(tmp_path: Path) -> None:
    target = tmp_path / "sample.txt"
    target.write_text("hello", encoding="utf-8")

    result = CliRunner().invoke(
        app, ["scan", str(target), "--allow-upload", "--no-network", "--quiet"]
    )

    combined = result.output
    # click mixes stderr into output by default; separated on newer versions.
    with contextlib.suppress(ValueError, AttributeError):  # pragma: no cover - version dep.
        combined += result.stderr or ""
    assert _WARNING in combined.lower(), f"no inert-flag warning in output:\n{combined}"
    # A real verdict (0-3), never the runtime-error code 4: the flag must not crash.
    assert result.exit_code != 4, f"scan crashed (exit 4):\n{combined}"
