"""install-desktop-entry.sh must bake a resolvable, GUI-launching Exec.

Regression guard for the dock name/icon on a source install: a bare ``Exec=prescan``
is only on PATH while the venv is active, so GLib cannot build a DesktopAppInfo for
the entry and GNOME shows the raw app-id with a generic gear. The installer therefore
rewrites Exec to an absolute ``<python> -m prescan``. Without this test someone could
simplify the script back to the bare name and the gear would return silently.

Hermetic: runs the script into a throwaway XDG_DATA_HOME, no network, no session.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell installer; Linux/macOS only")
def test_installed_exec_is_absolute_and_launches_the_gui_module(tmp_path: Path) -> None:
    env = {**os.environ, "XDG_DATA_HOME": str(tmp_path)}
    result = subprocess.run(
        ["bash", str(_REPO_ROOT / "packaging" / "install-desktop-entry.sh")],
        cwd=_REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"installer failed:\n{result.stdout}\n{result.stderr}"

    desktop = tmp_path / "applications" / "prescan.desktop"
    assert desktop.is_file(), "installer did not write the desktop entry"
    lines = desktop.read_text(encoding="utf-8").splitlines()
    exec_line = next(line for line in lines if line.startswith("Exec="))
    argv = shlex.split(exec_line[len("Exec=") :])

    # Absolute and executable -> GLib/GNOME can resolve the entry (not a bare name).
    assert argv[0].startswith("/"), f"Exec is not absolute: {exec_line}"
    assert os.access(argv[0], os.X_OK), f"Exec target is not executable: {argv[0]}"
    # Must launch the GUI module, not the CLI console script (which prints --help).
    assert argv[1:] == ["-m", "prescan"], f"Exec must run 'python -m prescan', got {argv[1:]}"
