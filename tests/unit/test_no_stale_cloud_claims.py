"""Guard against the old, now-false cloud-upload promises creeping back (G point 5).

M8 shipped consent-based cloud upload, so the earlier "not implemented / inert / the
file never leaves your machine" wording is wrong. This asserts the exact removed
phrases are absent from the user-facing README and the About screen -- a narrow test
on specific strings, not a vibe check.
"""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]

# The exact stale claims about cloud upload that M8 made false. Matched case-insensitively.
_STALE_CLOUD_PHRASES = (
    "cloud file upload is not implemented",
    "not implemented in this version",
    "inert placeholders",
    "inert in this version",
    "the file itself never leaves your machine",
    "files never leave your machine",
    "cloud file upload is not available in this version",
)


def _assert_clean(text: str, where: str) -> None:
    lowered = text.lower()
    for phrase in _STALE_CLOUD_PHRASES:
        assert phrase not in lowered, f"stale cloud-upload claim in {where}: {phrase!r}"


def test_readme_has_no_stale_cloud_claims() -> None:
    _assert_clean((_ROOT / "README.md").read_text(encoding="utf-8"), "README.md")


def test_about_screen_has_no_stale_cloud_claims() -> None:
    about = _ROOT / "src" / "prescan" / "ui" / "qml" / "pages" / "AboutPage.qml"
    _assert_clean(about.read_text(encoding="utf-8"), "AboutPage.qml")
