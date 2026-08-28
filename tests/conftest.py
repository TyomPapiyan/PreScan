"""Shared pytest fixtures and configuration.

Tests never touch the real network (spec §13): cloud providers are exercised
with respx. This file is extended as engines and providers land in later
milestones.
"""

from __future__ import annotations
