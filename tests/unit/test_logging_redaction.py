"""§10.5: API key values must never reach the logs."""

from __future__ import annotations

import pytest
import structlog

from prescan.core.config import configure_logging, redact_secrets


def test_redact_processor_masks_secret_fields() -> None:
    event = {"event": "call", "api_key": "SECRET123", "url": "https://x"}
    out = redact_secrets(None, "info", event)
    assert out["api_key"] == "***"
    assert out["url"] == "https://x"


def test_configured_logger_does_not_emit_key_value(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging()
    log = structlog.get_logger("prescan.test.redaction")
    log.info("provider.request", api_key="SUPER-SECRET-VALUE-XYZ", provider="virustotal")
    captured = capsys.readouterr().out
    assert "SUPER-SECRET-VALUE-XYZ" not in captured
    assert "***" in captured
