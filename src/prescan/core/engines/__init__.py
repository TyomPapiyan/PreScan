"""Local detection engines and their registry.

``build_engines`` wires the concrete engines from configuration in the fixed
stage order of §6. The pipeline decides, per engine, whether to run it based on
its ``availability`` probe.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from prescan.core.engines.base import Engine, ScanContext
from prescan.core.engines.clamav import ClamAVEngine
from prescan.core.engines.defender import DefenderEngine
from prescan.core.engines.documents import DocumentsEngine
from prescan.core.engines.ml_engine import MLEngine
from prescan.core.engines.static_pe import StaticPEEngine
from prescan.core.engines.yara_engine import YaraEngine

if TYPE_CHECKING:
    from prescan.core.config import AppConfig, Paths

__all__ = [
    "ClamAVEngine",
    "DefenderEngine",
    "DocumentsEngine",
    "Engine",
    "MLEngine",
    "ScanContext",
    "StaticPEEngine",
    "YaraEngine",
    "build_engines",
]


def build_engines(config: AppConfig, paths: Paths) -> list[Engine]:
    """Return the local engines in pipeline stage order (§6, stages 5-10)."""
    return [
        ClamAVEngine(config),
        YaraEngine(paths.yara_rules_dir),
        DefenderEngine(),
        StaticPEEngine(),
        DocumentsEngine(),
        MLEngine(paths.model_path, config.ml_threshold),
    ]
