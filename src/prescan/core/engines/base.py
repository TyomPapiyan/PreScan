"""Contract every local engine must satisfy."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Protocol, runtime_checkable

from prescan.core.models import Availability, FileInfo, Signal, SourceKind


@dataclass
class ScanContext:
    """Everything an engine may read. Engines never mutate it."""

    path: Path
    info: FileInfo
    cancel: asyncio.Event
    timeout_s: float
    workdir: Path  # isolated temp dir, engine-private scratch space


@runtime_checkable
class Engine(Protocol):
    """A local detection engine. Must never execute the scanned file."""

    name: ClassVar[str]
    kind: ClassVar[SourceKind]
    stage_id: ClassVar[str]

    async def availability(self) -> tuple[Availability, str]:
        """Cheap, side-effect-free readiness probe. Returns status and a detail string."""
        ...

    async def scan(self, ctx: ScanContext) -> list[Signal]:
        """Analyse the file and return zero or more signals.

        Must respect ctx.cancel and ctx.timeout_s. Must never raise on malformed
        input: catch everything and return a single Severity.INFO signal describing
        the parse failure instead.
        """
        ...
