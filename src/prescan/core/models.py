"""Data models shared by the whole engine. No Qt, no I/O here."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #


class Verdict(StrEnum):
    """Final user-facing conclusion about a target."""

    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    """How alarming a single signal is, on its own."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SourceKind(StrEnum):
    """Which layer of the engine produced a signal."""

    LOCAL_ENGINE = "local_engine"  # ClamAV, Defender, YARA-X
    STATIC_ANALYSIS = "static_analysis"  # LIEF, oletools, pikepdf
    ML = "ml"  # our own ONNX model
    CAPABILITY = "capability"  # capa
    CLOUD_REPUTATION = "cloud_reputation"  # hash / URL lookups
    CLOUD_SCAN = "cloud_scan"  # file was uploaded
    HEURISTIC = "heuristic"  # URL and filename heuristics


class TargetKind(StrEnum):
    FILE = "file"
    URL = "url"


class StageStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    SKIPPED = "skipped"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Availability(StrEnum):
    """Whether an engine or provider can run at all right now."""

    READY = "ready"
    NOT_INSTALLED = "not_installed"  # clamd absent, capa absent
    NO_RULES = "no_rules"  # YARA rules never downloaded
    NO_KEY = "no_key"  # API key missing
    NO_MODEL = "no_model"  # model.onnx absent
    OFFLINE = "offline"
    UNSUPPORTED_OS = "unsupported_os"
    DISABLED = "disabled"  # switched off by the user
    ERROR = "error"


# --------------------------------------------------------------------------- #
# Request
# --------------------------------------------------------------------------- #


class ScanRequest(BaseModel):
    """Everything the pipeline needs to know before it starts."""

    model_config = ConfigDict(extra="forbid")

    target_kind: TargetKind
    file_path: Path | None = None
    url: str | None = None

    # Privacy and network switches. Defaults are the private-by-default choice.
    allow_network: bool = True
    allow_cloud_upload: bool = False  # stage 13: the file leaves the machine
    allow_download: bool = False  # URL scan: fetch the body

    follow_redirects: bool = True
    max_download_bytes: int = 2 * 1024**3
    max_archive_depth: int = 5
    max_archive_ratio: int = 200  # zip-bomb guard
    timeout_s: float = 300.0
    force_refresh: bool = False  # ignore the local cache

    @model_validator(mode="after")
    def _exactly_one_target(self) -> ScanRequest:
        if self.target_kind is TargetKind.FILE and self.file_path is None:
            raise ValueError("file_path is required for a FILE request")
        if self.target_kind is TargetKind.URL and not self.url:
            raise ValueError("url is required for a URL request")
        if self.file_path is not None and self.url:
            raise ValueError("a request carries either a file_path or a url, never both")
        return self


# --------------------------------------------------------------------------- #
# Signal
# --------------------------------------------------------------------------- #


class Signal(BaseModel):
    """One atomic observation from one source. Immutable."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source: str  # stable id: "clamav", "yara-x", "virustotal", "ml"
    kind: SourceKind
    severity: Severity

    title_key: str  # i18n key, e.g. "signal.yara.match"
    title_en: str  # English fallback, always filled
    detail: str = ""  # human-readable specifics, already localised or raw
    detail_params: dict[str, Any] = Field(default_factory=dict)

    weight: int = 0  # contribution to risk_score, may be negative
    decisive: bool = False  # a hard rule fired; see scoring.py
    mitre: list[str] = Field(default_factory=list)  # ["T1055", "T1027"]
    data: dict[str, Any] = Field(default_factory=dict)  # raw payload for the report


# --------------------------------------------------------------------------- #
# Target descriptions
# --------------------------------------------------------------------------- #


class SignatureInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    present: bool
    valid: bool = False
    trusted_chain: bool = False
    subject: str | None = None
    issuer: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    error: str | None = None


class FileInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: Path
    name: str
    size: int
    declared_extension: str
    detected_type: str  # "PE32+ executable (GUI) x86-64"
    detected_mime: str  # "application/vnd.microsoft.portable-executable"
    extension_mismatch: bool = False

    md5: str
    sha1: str
    sha256: str
    imphash: str | None = None
    ssdeep: str | None = None

    signature: SignatureInfo | None = None


class UrlInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    original: str
    normalized: str
    final_url: str | None = None
    redirect_chain: list[str] = Field(default_factory=list)
    registrable_domain: str | None = None
    is_idn: bool = False
    punycode_host: str | None = None
    domain_age_days: int | None = None
    tls_valid: bool | None = None
    tls_issuer: str | None = None
    http_status: int | None = None
    content_type: str | None = None
    content_length: int | None = None
    content_disposition_filename: str | None = None


# --------------------------------------------------------------------------- #
# Progress
# --------------------------------------------------------------------------- #


class StageResult(BaseModel):
    """Progress record for one pipeline stage. Streamed to the UI live."""

    model_config = ConfigDict(extra="forbid")

    stage_id: str  # "identify", "clamav", "yara", "ml", ...
    title_key: str
    status: StageStatus = StageStatus.PENDING
    availability: Availability = Availability.READY
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_s: float | None = None
    summary: str = ""  # "clean", "2 148 rules", "not installed"
    error: str | None = None


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #


class ScanReport(BaseModel):
    """The complete, serialisable result of one scan."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    scan_id: str  # uuid4 hex
    app_version: str

    request: ScanRequest
    started_at: datetime
    finished_at: datetime
    duration_s: float

    file: FileInfo | None = None
    url: UrlInfo | None = None

    signals: list[Signal] = Field(default_factory=list)
    stages: list[StageResult] = Field(default_factory=list)

    verdict: Verdict
    risk_score: Annotated[int, Field(ge=0, le=100)]
    verdict_reason_key: str  # i18n key explaining WHY this verdict
    verdict_reason_en: str

    from_cache: bool = False
    incomplete: bool = False  # at least one source could not run
    unavailable_sources: list[str] = Field(default_factory=list)
