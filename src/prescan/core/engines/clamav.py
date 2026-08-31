"""ClamAV engine built on the async clamd client.

ClamAV is optional (§2.4): if clamd is not reachable the engine reports
``NOT_INSTALLED`` and the pipeline skips it. Files larger than the daemon's
stream limit are skipped per-file with a clear message (§16.9), not silently.
"""

from __future__ import annotations

from typing import ClassVar, Final

import structlog

from prescan.core.config import AppConfig
from prescan.core.engines.base import ScanContext
from prescan.core.engines.clamd_client import ClamdClient
from prescan.core.errors import ClamdError, EngineSkipped
from prescan.core.models import Availability, Severity, Signal, SourceKind
from prescan.core.scoring import weight

log = structlog.get_logger(__name__)

#: Matches StreamMaxLength (2000M) on the target deployment (§16.9).
CLAMAV_MAX_BYTES: Final = 2000 * 1024 * 1024


class ClamAVEngine:
    """Local ClamAV detection via the clamd INSTREAM command."""

    name: ClassVar[str] = "clamav"
    kind: ClassVar[SourceKind] = SourceKind.LOCAL_ENGINE
    stage_id: ClassVar[str] = "clamav"

    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def _client(self) -> ClamdClient | None:
        """Build a clamd client from config, or None if nothing is configured."""
        clamd = self._config.clamd
        if not clamd.socket and not clamd.host:
            return None
        return ClamdClient(
            socket=clamd.socket,
            host=clamd.host,
            port=clamd.port,
            timeout_s=self._config.scan_timeout_s,
        )

    async def availability(self) -> tuple[Availability, str]:
        """Ping clamd. Absent daemon -> NOT_INSTALLED (not an error)."""
        client = self._client()
        if client is None:
            return Availability.NOT_INSTALLED, "clamd is not configured"
        if await client.ping():
            return Availability.READY, "clamd is running"
        return Availability.NOT_INSTALLED, "clamd is not responding"

    async def scan(self, ctx: ScanContext) -> list[Signal]:
        """Scan the file with clamd. Never raises on malformed input (§10.4)."""
        client = self._client()
        if client is None:  # pragma: no cover - guarded by availability()
            return []

        if ctx.info.size > CLAMAV_MAX_BYTES:
            raise EngineSkipped(
                Availability.TOO_LARGE,
                f"file exceeds the {CLAMAV_MAX_BYTES // (1024 * 1024)} MiB engine limit",
            )

        try:
            result = await client.instream_file(ctx.path)
        except ClamdError as exc:
            raise EngineSkipped(Availability.ERROR, f"clamd error: {exc}") from exc

        if result.is_infected:
            name = result.signature or "unknown"
            return [
                Signal(
                    source=self.name,
                    kind=self.kind,
                    severity=Severity.CRITICAL,
                    title_key="signal.clamav.found",
                    title_en=f"ClamAV detection: {name}",
                    detail=name,
                    weight=weight("local_engine", "clamav_detection", 100),
                    decisive=True,
                    data={"signature": name},
                )
            ]
        if result.status == "ERROR":
            raise EngineSkipped(
                Availability.ERROR, f"clamd could not scan: {result.signature or 'error'}"
            )
        return []
