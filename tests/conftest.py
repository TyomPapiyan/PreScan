"""Shared pytest fixtures and configuration.

Tests never touch the real network (spec §13): cloud providers are exercised
with respx. The Qt UI tests run headless: the offscreen platform is selected
here, before pytest-qt (and thus Qt) initialises.
"""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
