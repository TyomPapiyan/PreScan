"""TLS certificate inspection (§7 stage 5).

Checks certificate validity, issuer and host match. The blocking socket/TLS
handshake runs in a worker thread. Any failure degrades to ``valid=None`` or
``valid=False`` rather than raising.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import structlog

log = structlog.get_logger(__name__)


@dataclass
class TlsResult:
    """Outcome of a TLS certificate inspection."""

    valid: bool | None = None
    issuer: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    host_match: bool | None = None
    error: str | None = None


async def inspect_tls(host: str, port: int = 443, *, timeout_s: float = 15.0) -> TlsResult:
    """Inspect the TLS certificate presented by ``host``. Never raises."""
    if not host:
        return TlsResult(error="no host")
    return await asyncio.to_thread(_inspect_sync, host, port, timeout_s)


def _inspect_sync(host: str, port: int, timeout_s: float) -> TlsResult:
    """Blocking handshake body executed in a worker thread."""
    context = ssl.create_default_context()
    try:
        with (
            socket.create_connection((host, port), timeout=timeout_s) as sock,
            context.wrap_socket(sock, server_hostname=host) as tls,
        ):
            cert = tls.getpeercert()
        return _from_cert(cert, host_match=True)
    except ssl.SSLCertVerificationError as exc:
        # Handshake completed but the certificate did not verify (expired,
        # self-signed, or wrong host): a suspicious signal, not an error.
        host_ok = "hostname mismatch" not in str(exc)
        return TlsResult(valid=False, host_match=host_ok, error=str(exc))
    except (OSError, ssl.SSLError) as exc:
        log.debug("tls.inspect_failed", host=host, error=str(exc))
        return TlsResult(valid=None, error=str(exc))


def _from_cert(cert: Mapping[str, Any] | None, *, host_match: bool) -> TlsResult:
    """Build a TlsResult from a verified peer certificate dict."""
    if not cert:
        return TlsResult(valid=True, host_match=host_match)
    issuer = _issuer(cert)
    not_before = _cert_time(cert.get("notBefore"))
    not_after = _cert_time(cert.get("notAfter"))
    return TlsResult(
        valid=True,
        issuer=issuer,
        not_before=not_before,
        not_after=not_after,
        host_match=host_match,
    )


def _issuer(cert: Mapping[str, Any]) -> str | None:
    """Flatten the certificate issuer RDN sequence into 'O' or 'CN'."""
    issuer = cert.get("issuer")
    if not isinstance(issuer, (list, tuple)):
        return None
    fields: dict[str, str] = {}
    for rdn in issuer:
        for pair in rdn:
            if isinstance(pair, (list, tuple)) and len(pair) == 2:
                fields[str(pair[0])] = str(pair[1])
    return fields.get("organizationName") or fields.get("commonName")


def _cert_time(raw: object) -> datetime | None:
    """Parse an OpenSSL certificate timestamp like 'Jun  1 00:00:00 2027 GMT'."""
    if not isinstance(raw, str):
        return None
    try:
        return datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
    except ValueError:
        return None
