"""Smoke test for package metadata and the CLI wiring (M0)."""

from __future__ import annotations

import prescan


def test_version_is_a_string() -> None:
    """The package exposes a non-empty ``__version__`` string."""
    assert isinstance(prescan.__version__, str)
    assert prescan.__version__
