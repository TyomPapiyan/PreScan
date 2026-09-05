"""Stage D: ``--allow-upload`` is a real consent flag now, not an inert placeholder.

These tests are hermetic: ``_run_scan`` is replaced by a spy so no pipeline and no
network run. They pin the CLI contract around the flag:

* the persistent lock (``never_upload_files``) beats the flag -> exit 4, nothing runs;
* with the lock closed the file never leaves the machine (preserved from the old file);
* ``--no-network`` beats the flag -> no consent reaches the request;
* on real consent, two stderr lines bracket the scan (permission before, fact after),
  the fact is read straight from the report, and ``--quiet`` silences neither;
* ``--json`` keeps stdout pure JSON while the two lines stay on stderr;
* for a URL with ``--download`` the notice names the downloaded file, not the address;
* the help text no longer calls the flag inert.

This file replaces the previous inert-flag test: that contract (a warning that upload
"is not implemented") is exactly what stage D removes, so asserting it would pin a
behaviour that no longer exists. The one durable claim from the old file -- with the
lock closed the file does not leave the machine -- is preserved below.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from prescan import cli
from prescan.core.config import AppConfig
from prescan.core.models import ScanReport, ScanRequest, Verdict

_UPLOADED_AT = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    """Drop ANSI colour codes so a rich-rendered flag name reads as one token.

    Rich colourises the help on a colour-capable terminal (as CI is), wrapping each
    flag as ``-`` ESC ``-allow-upload`` ESC, so the literal ``--allow-upload`` never
    appears contiguously. Stripping the escapes rejoins the two dashes.
    """
    return _ANSI.sub("", text)


def _config(*, never_upload: bool) -> AppConfig:
    cfg = AppConfig()
    cfg.never_upload_files = never_upload
    return cfg


def _report(
    request: ScanRequest, *, uploaded_to: str | None, uploaded_at: datetime | None
) -> ScanReport:
    now = datetime(2026, 9, 5, 12, 0, 5, tzinfo=UTC)
    return ScanReport(
        scan_id="deadbeef",
        app_version="0.1.0",
        request=request,
        started_at=now,
        finished_at=now,
        duration_s=0.0,
        verdict=Verdict.SAFE,
        risk_score=0,
        verdict_reason_key="reason.clean",
        verdict_reason_en="clean",
        uploaded_to=uploaded_to,
        uploaded_at=uploaded_at,
    )


def _install(
    monkeypatch: pytest.MonkeyPatch,
    *,
    never_upload: bool,
    uploaded_to: str | None = None,
    uploaded_at: datetime | None = None,
) -> list[ScanRequest]:
    """Wire a config and a spy ``_run_scan``; return the list of requests it saw."""
    seen: list[ScanRequest] = []
    cfg = _config(never_upload=never_upload)
    monkeypatch.setattr(cli.AppConfig, "load", staticmethod(lambda: cfg))

    async def _spy(request: ScanRequest, config: AppConfig) -> ScanReport:
        seen.append(request)
        return _report(request, uploaded_to=uploaded_to, uploaded_at=uploaded_at)

    monkeypatch.setattr(cli, "_run_scan", _spy)
    return seen


def _sample(tmp_path: Path) -> Path:
    target = tmp_path / "sample.txt"
    target.write_text("hello", encoding="utf-8")
    return target


# --- lock closed beats the flag (exit 4, zero requests, name the setting) -------- #
def test_lock_closed_refuses_flag_and_names_setting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _install(monkeypatch, never_upload=True)  # lock closed (the default)
    result = CliRunner().invoke(cli.app, ["scan", str(_sample(tmp_path)), "--allow-upload"])

    assert result.exit_code == 4
    assert seen == []  # nothing ran: no scan, no upload request
    assert "Never upload files to the cloud" in result.stderr


# --- lock closed -> the file does not leave the machine (preserved assertion) ---- #
def test_lock_closed_keeps_file_local_without_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _install(monkeypatch, never_upload=True)  # default lock, no --allow-upload
    result = CliRunner().invoke(cli.app, ["scan", str(_sample(tmp_path))])

    assert result.exit_code != 4
    assert len(seen) == 1
    # No consent ever reaches the pipeline, so the file stays put.
    assert seen[0].allow_cloud_upload is False
    assert "authorized" not in result.stderr.lower()


# --- --no-network beats the flag (no consent reaches the request) ---------------- #
def test_no_network_beats_allow_upload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _install(monkeypatch, never_upload=False)  # lock open, so we reach the scan
    result = CliRunner().invoke(
        cli.app, ["scan", str(_sample(tmp_path)), "--allow-upload", "--no-network"]
    )

    assert result.exit_code != 4
    assert len(seen) == 1
    assert seen[0].allow_cloud_upload is False  # consent did not reach the pipeline
    assert seen[0].allow_network is False
    assert "ignored" in result.stderr.lower()


# --- consent + upload happened: two lines, second matches the report ------------- #
def test_consent_upload_happened_reports_fact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _install(
        monkeypatch, never_upload=False, uploaded_to="virustotal", uploaded_at=_UPLOADED_AT
    )
    result = CliRunner().invoke(cli.app, ["scan", str(_sample(tmp_path)), "--allow-upload"])

    assert seen[0].allow_cloud_upload is True
    err = result.stderr
    # Before line: permission + service, announced ahead of the scan.
    assert "authorized" in err.lower() and "VirusTotal" in err
    # After line: the fact, taken straight from the report fields.
    assert "uploaded to virustotal" in err.lower()
    assert _UPLOADED_AT.isoformat() in err


# --- consent but the gate blocked the upload: second line says "not sent" -------- #
def test_consent_but_not_sent_reports_fact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _install(monkeypatch, never_upload=False, uploaded_to=None, uploaded_at=None)
    result = CliRunner().invoke(cli.app, ["scan", str(_sample(tmp_path)), "--allow-upload"])

    assert seen[0].allow_cloud_upload is True
    err = result.stderr
    assert "authorized" in err.lower()  # the before line was still present
    assert "not sent to the cloud" in err.lower()


# --- --quiet silences neither the before nor the after line ---------------------- #
def test_quiet_does_not_silence_upload_lines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install(monkeypatch, never_upload=False, uploaded_to="virustotal", uploaded_at=_UPLOADED_AT)
    result = CliRunner().invoke(
        cli.app, ["scan", str(_sample(tmp_path)), "--allow-upload", "--quiet"]
    )

    err = result.stderr
    assert "authorized" in err.lower()
    assert "uploaded to virustotal" in err.lower()


# --- --json: stdout is pure JSON with the fields; notices stay on stderr --------- #
def test_json_stdout_is_pure_json_notices_on_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install(monkeypatch, never_upload=False, uploaded_to="virustotal", uploaded_at=_UPLOADED_AT)
    result = CliRunner().invoke(
        cli.app, ["scan", str(_sample(tmp_path)), "--allow-upload", "--json"]
    )

    parsed = json.loads(result.stdout)  # stdout parses whole as JSON
    assert parsed["uploaded_to"] == "virustotal"
    assert parsed["uploaded_at"] is not None
    # The two notices are present, but only on stderr -- never mixed into stdout.
    assert "authorized" in result.stderr.lower()
    assert "uploaded to virustotal" in result.stderr.lower()
    assert "authorized" not in result.stdout.lower()


# --- URL + --download: the notice names the downloaded file, not the address ----- #
def test_url_download_notice_names_downloaded_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install(monkeypatch, never_upload=False, uploaded_to="virustotal", uploaded_at=_UPLOADED_AT)
    url = "https://example.com/payload.bin"
    result = CliRunner().invoke(cli.app, ["scan", url, "--download", "--allow-upload"])

    err = result.stderr.lower()
    assert "downloaded file" in err
    assert url not in result.stderr  # the address itself is not part of the notice


# --- help text no longer calls the flag inert ----------------------------------- #
def test_help_does_not_call_flag_inert() -> None:
    result = CliRunner().invoke(cli.app, ["scan", "--help"])
    text = _plain(result.output).lower()
    assert "inert" not in text
    assert "not implemented" not in text
    assert "--allow-upload" in _plain(result.output)
