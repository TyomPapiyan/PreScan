"""Exception hierarchy for the engine.

All engine-raised errors derive from :class:`PreScanError`. Parsing of
untrusted input must never leak these to the pipeline: engines catch everything
and turn failures into an ``INFO`` signal (§10.4). These types exist for the
few places where raising is the right control-flow choice (archive guards,
clamd protocol errors) and for precise tests.
"""

from __future__ import annotations


class PreScanError(Exception):
    """Base class for every PreScan-specific error."""


class ConfigError(PreScanError):
    """Configuration could not be loaded or validated."""


class EngineError(PreScanError):
    """A local engine failed in a way that is not a parse error."""


class EngineSkipped(PreScanError):  # noqa: N818 - control-flow signal, not a fault
    """An engine intentionally skips this file (e.g. clamd 2 GiB limit, §16.9).

    Carries the availability reason and a human summary so the pipeline can mark
    the stage SKIPPED and surface it to the user rather than swallowing it.
    """

    def __init__(self, availability: str, summary: str) -> None:
        super().__init__(summary)
        self.availability = availability
        self.summary = summary


class ClamdError(EngineError):
    """The clamd protocol client failed to talk to the daemon."""


class ClamdUnavailableError(ClamdError):
    """clamd could not be reached (socket missing, connection refused)."""


class ClamdProtocolError(ClamdError):
    """clamd returned a malformed or unexpected response."""


class ArchiveError(PreScanError):
    """Base class for archive-handling failures."""


class ArchiveBombError(ArchiveError):
    """An archive tripped a decompression-bomb guard (ratio/size/count/depth)."""


class ArchiveTraversalError(ArchiveError):
    """An archive entry tried to escape the extraction directory."""


class ParseError(PreScanError):
    """Untrusted content could not be parsed. Usually caught, not raised."""


class DownloadError(PreScanError):
    """A network download failed or exceeded its size/time limits."""


class UpdateError(PreScanError):
    """Fetching or installing rules (YARA Forge, capa) failed."""
