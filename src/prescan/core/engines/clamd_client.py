"""Minimal asynchronous client for the clamd protocol.

We talk to the ``clamd`` daemon over a unix socket or TCP and never link
libclamav (§10.2). Only the handful of commands we need are implemented, using
newline-terminated ``n`` commands and the ``INSTREAM`` chunked upload.

The server has ``MaxScanTime=0`` on this deployment, so hang protection lives
here: every network operation is wrapped in a client-side timeout.
"""

from __future__ import annotations

import asyncio
import contextlib
import struct
from pathlib import Path
from typing import Final, cast

import structlog

from prescan.core.errors import ClamdProtocolError, ClamdUnavailableError

log = structlog.get_logger(__name__)

_CHUNK: Final = 64 * 1024
#: clamd rejects INSTREAM chunks larger than StreamMaxLength; stay well under.
_MAX_CHUNK: Final = 1024 * 1024
_END_MARK: Final = struct.pack("!I", 0)


class ScanResult:
    """Outcome of an INSTREAM scan: status plus optional signature name."""

    __slots__ = ("signature", "status")

    def __init__(self, status: str, signature: str | None = None) -> None:
        self.status = status  # "OK" | "FOUND" | "ERROR"
        self.signature = signature

    @property
    def is_infected(self) -> bool:
        return self.status == "FOUND"

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"ScanResult(status={self.status!r}, signature={self.signature!r})"


class ClamdClient:
    """Async clamd client over a unix socket (preferred) or TCP."""

    def __init__(
        self,
        *,
        socket: str | None = None,
        host: str | None = None,
        port: int = 3310,
        timeout_s: float = 60.0,
    ) -> None:
        if not socket and not host:
            raise ValueError("clamd client needs either a unix socket or a host")
        self._socket = socket
        self._host = host
        self._port = port
        self._timeout_s = timeout_s

    async def _open(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Open a connection to clamd, raising ClamdUnavailableError on failure."""
        try:
            if self._socket:
                # open_unix_connection is Unix-only; resolve it dynamically so the
                # module still type-checks on Windows (where clamd is reached by TCP).
                open_unix = getattr(asyncio, "open_unix_connection", None)
                if open_unix is None:
                    raise ClamdUnavailableError("unix sockets are not supported on this OS")
                return cast(
                    "tuple[asyncio.StreamReader, asyncio.StreamWriter]",
                    await open_unix(self._socket),
                )
            assert self._host is not None
            return await asyncio.open_connection(self._host, self._port)
        except (TimeoutError, OSError) as exc:
            raise ClamdUnavailableError(f"cannot reach clamd: {exc}") from exc

    async def _command(self, command: bytes) -> str:
        """Send a simple ``n`` command and return the single-line reply."""
        async with asyncio.timeout(self._timeout_s):
            reader, writer = await self._open()
            try:
                writer.write(command)
                await writer.drain()
                line = await reader.readline()
            finally:
                writer.close()
                with contextlib.suppress(OSError):
                    await writer.wait_closed()
        return line.decode("utf-8", "replace").strip()

    async def ping(self) -> bool:
        """Return True if clamd answers PING with PONG."""
        try:
            return await self._command(b"nPING\n") == "PONG"
        except (TimeoutError, ClamdUnavailableError):
            return False

    async def version(self) -> str:
        """Return the clamd version banner (may be empty)."""
        try:
            return await self._command(b"nVERSION\n")
        except (TimeoutError, ClamdUnavailableError):
            return ""

    async def reload(self) -> str:
        """Send RELOAD; return the daemon's reply ('RELOADING' on success).

        Some deployments disable the command and answer 'COMMAND UNAVAILABLE';
        the caller must surface that rather than assume the reload happened.
        """
        try:
            return await self._command(b"nRELOAD\n")
        except (TimeoutError, ClamdUnavailableError) as exc:
            return f"error: {exc}"

    async def instream_file(self, path: Path) -> ScanResult:
        """Scan a file by streaming its bytes to clamd via INSTREAM."""
        async with asyncio.timeout(self._timeout_s):
            reader, writer = await self._open()
            try:
                writer.write(b"nINSTREAM\n")
                await writer.drain()
                await self._stream_file(path, writer)
                writer.write(_END_MARK)
                await writer.drain()
                line = await reader.readline()
            finally:
                writer.close()
                with contextlib.suppress(OSError):
                    await writer.wait_closed()
        return self._parse_scan_reply(line.decode("utf-8", "replace").strip())

    async def _stream_file(self, path: Path, writer: asyncio.StreamWriter) -> None:
        """Read the file in a worker thread and push INSTREAM chunks."""
        loop = asyncio.get_running_loop()
        with path.open("rb") as fh:
            while True:
                chunk = await loop.run_in_executor(None, fh.read, _CHUNK)
                if not chunk:
                    break
                if len(chunk) > _MAX_CHUNK:  # pragma: no cover - defensive
                    chunk = chunk[:_MAX_CHUNK]
                writer.write(struct.pack("!I", len(chunk)))
                writer.write(chunk)
                await writer.drain()

    @staticmethod
    def _parse_scan_reply(reply: str) -> ScanResult:
        """Parse a clamd stream reply into a ScanResult."""
        # Examples:
        #   "stream: OK"
        #   "stream: Win.Test.EICAR_HDB-1 FOUND"
        #   "stream: INSTREAM size limit exceeded ERROR"
        if not reply:
            raise ClamdProtocolError("empty reply from clamd")
        body = reply.split(":", 1)[1].strip() if ":" in reply else reply
        if body.endswith("FOUND"):
            signature = body[: -len("FOUND")].strip()
            return ScanResult("FOUND", signature or None)
        if body.endswith("ERROR"):
            message = body[: -len("ERROR")].strip()
            return ScanResult("ERROR", message or None)
        if body.endswith("OK"):
            return ScanResult("OK")
        raise ClamdProtocolError(f"unexpected clamd reply: {reply!r}")
