"""Shared pytest fixtures and configuration.

Tests never touch the real network (spec §13): cloud providers are exercised
with respx. The Qt UI tests run headless: the offscreen platform is selected
here, before pytest-qt (and thus Qt) initialises.
"""

from __future__ import annotations

import os
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# Isolate config/data/cache dirs so tests never read or write the real user
# config, database, quarantine or keyring-adjacent files. platformdirs honours
# these XDG variables on Linux; must be set before prescan.core.config imports.
_TEST_HOME = tempfile.mkdtemp(prefix="prescan-test-home-")
os.environ.setdefault("XDG_CONFIG_HOME", os.path.join(_TEST_HOME, "config"))
os.environ.setdefault("XDG_DATA_HOME", os.path.join(_TEST_HOME, "data"))
os.environ.setdefault("XDG_CACHE_HOME", os.path.join(_TEST_HOME, "cache"))
