"""`python -m prescan` must launch the GUI, not the CLI (spec §4)."""

from __future__ import annotations

import pytest


def test_module_entrypoint_calls_gui_run(monkeypatch: pytest.MonkeyPatch) -> None:
    import prescan.__main__ as entry
    import prescan.ui.app as uiapp

    called: dict[str, bool] = {}
    monkeypatch.setattr(uiapp, "run", lambda: called.setdefault("run", True) or 0)
    entry.main()
    assert called.get("run") is True


def test_module_entrypoint_does_not_use_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    import prescan.cli as cli
    import prescan.ui.app as uiapp

    monkeypatch.setattr(uiapp, "run", lambda: 0)
    monkeypatch.setattr(
        cli, "app", lambda *a, **k: pytest.fail("module entry must not invoke the CLI")
    )
    import prescan.__main__ as entry

    entry.main()
