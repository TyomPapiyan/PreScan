"""Application configuration, data paths and keyring access.

``AppConfig`` is a pydantic model with validation and defaults. A broken config
file never crashes the app: the loader logs a warning and falls back to defaults
(spec §14). Paths come from ``platformdirs`` for the ``PreScan`` app.

API keys are read from the OS keyring only (service ``prescan``), never from the
config file, the repo, logs or reports (§10.5). Keyring wiring is exercised on
M2; the accessors live here so the rest of the engine has a single entry point.
"""

from __future__ import annotations

import contextlib
import sys
import tomllib
from collections.abc import MutableMapping
from pathlib import Path
from typing import Any, Final

import structlog
from platformdirs import PlatformDirs
from pydantic import BaseModel, ConfigDict, Field

from prescan.core.errors import ConfigError

log = structlog.get_logger(__name__)

#: Log field names whose values must never be written out (§10.5).
_SENSITIVE_FIELDS: Final = frozenset(
    {
        "api_key",
        "apikey",
        "key",
        "auth",
        "auth-key",
        "auth_key",
        "authorization",
        "x-apikey",
        "token",
        "password",
        "secret",
    }
)


def redact_secrets(
    _logger: object, _method: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """structlog processor: replace secret field values with ``***`` (§10.5)."""
    for field in list(event_dict):
        if field.lower() in _SENSITIVE_FIELDS:
            event_dict[field] = "***"
    return event_dict


def configure_logging() -> None:
    """Configure structlog with secret redaction as a mandatory processor."""
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            redact_secrets,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        cache_logger_on_first_use=True,
    )


_DIRS: Final = PlatformDirs(appname="PreScan", appauthor="PreScan")

#: Keyring service name shared by every provider (spec §14).
KEYRING_SERVICE: Final = "prescan"

#: Provider ids used as keyring usernames.
PROVIDER_IDS: Final = (
    "virustotal",
    "metadefender",
    "malwarebazaar",
    "safebrowsing",
    "urlscan",
)


def _default_clamd_socket() -> str | None:
    """Return the default clamd unix socket for this OS, or None on Windows."""
    if sys.platform.startswith("win"):
        return None
    # Ubuntu/Debian ClamAV ships this path; permissions 0666, no root needed.
    return "/var/run/clamav/clamd.ctl"


class Paths(BaseModel):
    """Resolved on-disk locations for config, data, cache and logs."""

    model_config = ConfigDict(frozen=True)

    config_dir: Path
    data_dir: Path
    cache_dir: Path
    db_path: Path
    quarantine_dir: Path
    tmp_dir: Path
    logs_dir: Path
    yara_rules_dir: Path
    capa_rules_dir: Path
    model_path: Path

    @classmethod
    def resolve(cls) -> Paths:
        """Build the standard path layout from platformdirs (§14)."""
        config_dir = Path(_DIRS.user_config_dir)
        data_dir = Path(_DIRS.user_data_dir)
        cache_dir = Path(_DIRS.user_cache_dir)
        return cls(
            config_dir=config_dir,
            data_dir=data_dir,
            cache_dir=cache_dir,
            db_path=data_dir / "prescan.db",
            quarantine_dir=data_dir / "quarantine",
            tmp_dir=cache_dir / "tmp",
            logs_dir=cache_dir / "logs",
            yara_rules_dir=data_dir / "yara",
            capa_rules_dir=data_dir / "capa",
            model_path=data_dir / "model.onnx",
        )

    def ensure(self) -> None:
        """Create every directory that must exist, with private tmp (0o700)."""
        for directory in (
            self.config_dir,
            self.data_dir,
            self.cache_dir,
            self.quarantine_dir,
            self.logs_dir,
            self.yara_rules_dir,
            self.capa_rules_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        # Temp files hold untrusted downloads/extractions: keep them private.
        self.tmp_dir.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):  # pragma: no cover - platform dependent
            self.tmp_dir.chmod(0o700)


class ClamdSettings(BaseModel):
    """How to reach the clamd daemon. Unix socket takes precedence over TCP."""

    model_config = ConfigDict(extra="forbid")

    socket: str | None = Field(default_factory=_default_clamd_socket)
    host: str | None = None
    port: int = 3310


class AppConfig(BaseModel):
    """User-facing configuration with private-by-default network posture."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    # --- network / privacy (defaults mirror §9.7 privacy switches) ---
    allow_network: bool = True
    never_upload_files: bool = True
    only_send_hashes: bool = True

    # --- engines ---
    clamd: ClamdSettings = Field(default_factory=ClamdSettings)
    enabled_engines: dict[str, bool] = Field(default_factory=dict)
    ml_threshold: float = 0.70

    # --- scanning limits ---
    cache_ttl_days: int = 7
    max_download_bytes: int = 2 * 1024**3
    max_archive_depth: int = 5
    max_archive_ratio: int = 200
    connect_timeout_s: float = 15.0
    scan_timeout_s: float = 300.0

    # --- UI ---
    language: str = "system"
    theme: str = "system"

    def engine_enabled(self, name: str) -> bool:
        """Return whether an engine is enabled (default: enabled)."""
        return self.enabled_engines.get(name, True)

    @classmethod
    def load(cls, path: Path | None = None) -> AppConfig:
        """Load config from TOML, falling back to defaults on any problem.

        A malformed or unreadable file never raises to the caller: it is logged
        and defaults are used (§14). Pass ``path`` to override the location.
        """
        cfg_path = path or (Paths.resolve().config_dir / "config.toml")
        if not cfg_path.exists():
            return cls()
        try:
            with cfg_path.open("rb") as fh:
                raw: dict[str, Any] = tomllib.load(fh)
            return cls.model_validate(raw)
        except (OSError, tomllib.TOMLDecodeError, ValueError) as exc:
            log.warning("config.load.failed", path=str(cfg_path), error=str(exc))
            return cls()


def get_api_key(provider_id: str) -> str | None:
    """Return the API key for a provider from the OS keyring, or None.

    Never falls back to environment/config for secrets. Keyring failures are
    swallowed and reported as a missing key so a broken backend degrades to
    ``NO_KEY`` rather than crashing (§10.5).
    """
    if provider_id not in PROVIDER_IDS:
        raise ConfigError(f"unknown provider id: {provider_id!r}")
    try:
        import keyring

        return keyring.get_password(KEYRING_SERVICE, provider_id)
    except Exception as exc:  # noqa: BLE001 - keyring backends raise many types
        log.warning("keyring.get.failed", provider=provider_id, error=str(exc))
        return None
