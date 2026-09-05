"""Smoke test for package metadata and the CLI wiring (M0)."""

from __future__ import annotations

from pathlib import Path

import prescan

_ROOT = Path(__file__).resolve().parents[2]


def test_version_is_a_string() -> None:
    """The package exposes a non-empty ``__version__`` string."""
    assert isinstance(prescan.__version__, str)
    assert prescan.__version__


def test_release_notes_exist_for_current_version() -> None:
    """The release notes file name matches __version__ (docs-level version guard, G point 15).

    CI already fails a tag build when the tag != v + __version__; this closes the same
    gap in the docs, locally: a version bump without its notes file fails the gate.
    """
    notes = _ROOT / "docs" / "release-notes" / f"v{prescan.__version__}.md"
    assert notes.is_file(), f"missing release notes: {notes.relative_to(_ROOT)}"
