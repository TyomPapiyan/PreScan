"""EICAR test-string fixture.

The EICAR string is assembled at runtime from parts so that no antivirus flags
the repository and the full string never appears verbatim in the sources
(spec §13.1). The result is a harmless standard AV test file.
"""

from __future__ import annotations


def eicar_bytes() -> bytes:
    """Assemble the EICAR test string at runtime, so no AV flags the repo."""
    parts = [
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-",
        "ANTIVIRUS-TEST-FILE!$H+H*",
    ]
    return "".join(parts).encode("ascii")
