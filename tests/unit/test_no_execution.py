"""§10.3 guard: the engine core must never execute the scanned file.

Greps every ``prescan.core`` source for OS-association / launch calls. This is a
blocking architectural rule, checked in CI.
"""

from __future__ import annotations

from pathlib import Path

import prescan.core

_BANNED_TOKENS = (
    "os.startfile",
    "ShellExecute",
    "xdg-open",
    "webbrowser.open",
    "os.system(",
)


def _core_sources() -> list[Path]:
    root = Path(prescan.core.__path__[0])
    return sorted(root.rglob("*.py"))


def test_core_has_no_file_execution_calls() -> None:
    offenders: list[str] = []
    for path in _core_sources():
        text = path.read_text(encoding="utf-8")
        for token in _BANNED_TOKENS:
            if token in text:
                offenders.append(f"{path.name}: {token}")
    assert not offenders, f"banned execution calls found: {offenders}"
