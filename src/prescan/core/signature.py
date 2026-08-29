"""Code-signing inspection: Authenticode for PE, best-effort for ELF.

LIEF parses and cryptographically verifies the embedded Authenticode chain on
any OS, so PE signatures are checked even on Linux. ``trusted_chain`` reflects
LIEF's embedded-chain verification, not the host OS trust store. ELF binaries
carry no standard code signature, so they report ``present=False``.

Untrusted input: every failure is caught and turned into ``present=False`` with
an ``error`` string (§10.4) — signature parsing never crashes the pipeline.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import structlog

from prescan.core.models import Severity, Signal, SignatureInfo, SourceKind
from prescan.core.scoring import weight

log = structlog.get_logger(__name__)

_SOURCE = "signature"


def _to_datetime(value: Any) -> datetime | None:
    """Convert LIEF's ``valid_from``/``valid_to`` list into a datetime."""
    try:
        parts = list(value)
        if len(parts) >= 6:
            year, month, day, hour, minute, second = parts[:6]
            return datetime(year, month, day, hour, minute, second)
    except (TypeError, ValueError):
        return None
    return None


def get_signature(path: Path) -> SignatureInfo:
    """Return signing status for a file. Never raises."""
    try:
        import lief

        binary = lief.parse(str(path))
        if binary is None:
            return SignatureInfo(present=False, error="unparsable binary")
        if not isinstance(binary, lief.PE.Binary):
            # ELF/Mach-O: no standard embedded code signature we verify here.
            return SignatureInfo(present=False)

        signatures = list(binary.signatures)
        if not signatures:
            return SignatureInfo(present=False)

        flags = binary.verify_signature()
        ok = flags == lief.PE.Signature.VERIFICATION_FLAGS.OK

        subject = issuer = None
        not_before = not_after = None
        signers = list(signatures[0].signers)
        if signers and signers[0].cert is not None:
            cert = signers[0].cert
            subject = str(cert.subject) if cert.subject else None
            issuer = str(cert.issuer) if cert.issuer else None
            not_before = _to_datetime(cert.valid_from)
            not_after = _to_datetime(cert.valid_to)

        return SignatureInfo(
            present=True,
            valid=ok,
            trusted_chain=ok,
            subject=subject,
            issuer=issuer,
            not_before=not_before,
            not_after=not_after,
            error=None if ok else str(flags),
        )
    except Exception as exc:  # noqa: BLE001 - untrusted binary, never crash (§10.4)
        log.debug("signature.parse_failed", path=str(path), error=str(exc))
        return SignatureInfo(present=False, error=f"signature parse failed: {exc}")


def signature_signals(info: SignatureInfo) -> list[Signal]:
    """Turn signing status into scored signals (§8.4/§8.6).

    A valid, trusted signature contributes a negative weight and marks the
    file so the scoring layer can suppress packing-only escalation. An absent
    signature contributes a small positive weight but never escalates on its own.
    """
    if info.present and info.valid and info.trusted_chain:
        return [
            Signal(
                source=_SOURCE,
                kind=SourceKind.STATIC_ANALYSIS,
                severity=Severity.INFO,
                title_key="signal.signature.trusted",
                title_en="Valid, trusted code signature",
                detail=info.subject or "",
                weight=weight("static", "valid_trusted_signature", -25),
                data={"valid_trusted_signature": True, "subject": info.subject},
            )
        ]
    if not info.present:
        return [
            Signal(
                source=_SOURCE,
                kind=SourceKind.STATIC_ANALYSIS,
                severity=Severity.INFO,
                title_key="signal.signature.absent",
                title_en="File is not code-signed",
                weight=weight("static", "no_signature", 8),
                data={"signed": False},
            )
        ]
    # Present but invalid/untrusted: informational, small weight, no escalation.
    return [
        Signal(
            source=_SOURCE,
            kind=SourceKind.STATIC_ANALYSIS,
            severity=Severity.INFO,
            title_key="signal.signature.invalid",
            title_en="Code signature present but not trusted",
            detail=info.error or "",
            weight=weight("static", "no_signature", 8),
            data={"signed": True, "valid": False},
        )
    ]
