"""URL pipeline (§7) end-to-end with network calls stubbed.

Providers are skipped via a keyless keyring; RDAP/TLS/redirect network calls are
monkeypatched to canned results so the stage wiring and scoring are exercised
without touching the network (§13).
"""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
import respx

import prescan.core.config as config_mod
import prescan.core.pipeline as pipeline_mod
from prescan.core.config import AppConfig
from prescan.core.models import (
    Availability,
    ScanRequest,
    Severity,
    Signal,
    SourceKind,
    StageStatus,
    TargetKind,
    UploadOutcome,
    Verdict,
)
from prescan.core.pipeline import STAGE_REPUTATION, STAGE_URL_REPUTATION, Pipeline
from prescan.core.url.inspector import InspectResult
from prescan.core.url.tls import TlsResult


@pytest.mark.asyncio
async def test_url_pipeline_scores_risky_signals(monkeypatch: pytest.MonkeyPatch) -> None:
    # No provider keys -> URL providers are SKIPPED (NO_KEY), no network.
    monkeypatch.setattr(config_mod, "get_api_key", lambda _pid: None)

    async def fake_age(_domain: str, *, timeout_s: float = 15.0) -> int:
        return 5  # young domain -> risk

    async def fake_tls(_host: str, port: int = 443, *, timeout_s: float = 15.0) -> TlsResult:
        return TlsResult(valid=False, host_match=False, error="expired")

    async def fake_inspect(url: str, **_kw: object) -> InspectResult:
        return InspectResult(
            final_url="https://evil.ru/",
            redirect_chain=["https://evil.ru/"],
            registrable_changed=True,
            http_status=200,
        )

    monkeypatch.setattr(pipeline_mod, "domain_age_days", fake_age)
    monkeypatch.setattr(pipeline_mod, "inspect_tls", fake_tls)
    monkeypatch.setattr(pipeline_mod, "inspect_url", fake_inspect)

    request = ScanRequest(
        target_kind=TargetKind.URL, url="https://good-site.com/login", allow_network=True
    )
    report = await Pipeline(AppConfig.load()).run(request)

    stage_ids = {s.stage_id for s in report.stages}
    assert {"url_normalize", "url_heuristics", "domain_age", "tls", "redirects"} <= stage_ids
    assert report.url is not None
    assert report.url.domain_age_days == 5
    assert report.url.tls_valid is False
    # Young domain + invalid TLS + registrable-domain change -> SUSPICIOUS.
    assert report.verdict is Verdict.SUSPICIOUS

    rep_stages = [s for s in report.stages if s.title_key == "stage.url_reputation"]
    assert rep_stages and all(s.status is StageStatus.SKIPPED for s in rep_stages)


@pytest.mark.asyncio
async def test_url_pipeline_offline_only_local(monkeypatch: pytest.MonkeyPatch) -> None:
    request = ScanRequest(
        target_kind=TargetKind.URL, url="https://example.com/", allow_network=False
    )
    report = await Pipeline(AppConfig.load()).run(request)
    stage_ids = {s.stage_id for s in report.stages}
    assert "url_normalize" in stage_ids
    assert "domain_age" not in stage_ids  # network stages skipped offline
    assert report.verdict in {Verdict.UNKNOWN, Verdict.SAFE}


# --------------------------------------------------------------------------- #
# F0: hash reputation for the downloaded body, with the §8.3 asymmetry
# --------------------------------------------------------------------------- #
class _BodyHash:
    """A hash provider (stage-11 shape) returning canned signals for the body."""

    name = "virustotal"
    kind = SourceKind.CLOUD_REPUTATION
    stage_id = "reputation"
    requires_key = True

    def __init__(self, signals: list[Signal], *, raises: bool = False) -> None:
        self._signals = signals
        self._raises = raises

    async def availability(self) -> tuple[Availability, str]:
        return Availability.READY, "ready"

    async def lookup_hash(self, sha256: str) -> list[Signal]:
        if self._raises:
            raise RuntimeError("body reputation failed")
        return list(self._signals)


class _BodyUpload:
    """A stage-13 upload provider (shape only) returning a canned outcome."""

    name = "virustotal"
    supports_upload = True
    max_upload_bytes = 1_000_000

    def __init__(self, outcome: UploadOutcome) -> None:
        self._outcome = outcome
        self.upload_calls = 0

    async def availability(self) -> tuple[Availability, str]:
        return Availability.READY, "ready"

    async def upload_file(self, path: Path, *, cancel: object = None) -> UploadOutcome:
        self.upload_calls += 1
        return self._outcome


def _benign_url_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    body: list[Signal],
    *,
    hash_raises: bool = False,
    upload: _BodyUpload | None = None,
) -> list[Path]:
    """Wire a benign URL environment + a fake download + fake body providers.

    Returns the list of temp dirs the fake download created, so a test can assert they
    were cleaned up. URL reputation providers are stubbed to none, so ``incomplete``
    reflects only the download/body path.
    """
    monkeypatch.setattr(config_mod, "get_api_key", lambda _pid: None)
    created: list[Path] = []

    async def old_age(_domain: str, *, timeout_s: float = 15.0) -> int:
        return 400  # old domain -> no risk signal

    async def good_tls(_host: str, port: int = 443, *, timeout_s: float = 15.0) -> TlsResult:
        return TlsResult(valid=True, host_match=True)

    async def plain_inspect(url: str, **_kw: object) -> InspectResult:
        return InspectResult(
            final_url=url, redirect_chain=[url], registrable_changed=False, http_status=200
        )

    async def no_engines(self: Pipeline, *a: object, **k: object) -> tuple[list[Signal], bool]:
        return [], False

    async def fake_download(url: str, tmp_dir: Path, **_kw: object) -> Path:
        d = Path(tempfile.mkdtemp(dir=tmp_path))
        created.append(d)
        f = d / "download.bin"
        f.write_bytes(b"payload")
        return f

    monkeypatch.setattr(pipeline_mod, "domain_age_days", old_age)
    monkeypatch.setattr(pipeline_mod, "inspect_tls", good_tls)
    monkeypatch.setattr(pipeline_mod, "inspect_url", plain_inspect)
    monkeypatch.setattr(pipeline_mod, "safe_download", fake_download)
    monkeypatch.setattr(Pipeline, "_run_engines", no_engines)
    monkeypatch.setattr(pipeline_mod, "build_url_providers", lambda *a, **k: [])
    monkeypatch.setattr(
        pipeline_mod, "build_hash_providers", lambda *a, **k: [_BodyHash(body, raises=hash_raises)]
    )
    if upload is not None:
        monkeypatch.setattr(pipeline_mod, "build_upload_provider", lambda *a, **k: upload)
    return created


def _url_request(*, allow_cloud_upload: bool = False) -> ScanRequest:
    return ScanRequest(
        target_kind=TargetKind.URL,
        url="https://good-site.com/file",
        allow_network=True,
        allow_download=True,
        allow_cloud_upload=allow_cloud_upload,
    )


def _config(*, never_upload: bool) -> AppConfig:
    cfg = AppConfig.load()
    cfg.never_upload_files = never_upload
    return cfg


_SENT_AT = datetime(2026, 9, 12, 12, 0, tzinfo=UTC)


@pytest.mark.asyncio
async def test_downloaded_body_known_malicious_makes_url_dangerous(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Point 16: a known-malicious body behind a link is a dangerous link, in full."""
    malicious = Signal(
        source="malwarebazaar",
        kind=SourceKind.CLOUD_REPUTATION,
        severity=Severity.CRITICAL,
        title_key="signal.mb.hit",
        title_en="Known malware sample",
        decisive=True,
        weight=100,
    )
    _benign_url_env(monkeypatch, tmp_path, [malicious])
    report = await Pipeline(AppConfig.load()).run(_url_request())
    assert report.verdict is Verdict.DANGEROUS


@pytest.mark.asyncio
async def test_downloaded_body_clean_by_hash_keeps_url_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Point 17 (the main test): a clean body hash does NOT make the link SAFE.

    A clean hash is authoritative for the file, not for the link -- a URL can serve
    different content -- so the verdict stays UNKNOWN. If this ever turns SAFE, §8.3 is
    broken. It is asserted != SAFE (not just == UNKNOWN) so it cannot pass by accident.
    """
    clean = Signal(
        source="virustotal",
        kind=SourceKind.CLOUD_REPUTATION,
        severity=Severity.INFO,
        title_key="signal.vt.clean",
        title_en="VirusTotal: file known, clean",
        data={"authoritative_clean": True},
    )
    _benign_url_env(monkeypatch, tmp_path, [clean])
    report = await Pipeline(AppConfig.load()).run(_url_request())
    assert report.verdict is not Verdict.SAFE
    assert report.verdict is Verdict.UNKNOWN
    # The clean body signal is present and honestly authoritative-clean about the body...
    body_clean = next(s for s in report.signals if s.data.get("authoritative_clean") is True)
    assert body_clean.data.get("target_scope") == "downloaded_body"  # ...but scoped to the body


# --------------------------------------------------------------------------- #
# F0: stage 13 (cloud upload) in the URL branch
# --------------------------------------------------------------------------- #
def _outcome(**kw: object) -> UploadOutcome:
    base: dict[str, object] = {
        "sent": True,
        "sent_at": _SENT_AT,
        "availability": Availability.READY,
    }
    base.update(kw)
    return UploadOutcome(**base)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_url_body_upload_happens_and_fills_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Point 18: unknown body + consent + lock off -> upload runs, report fields filled."""
    up = _BodyUpload(_outcome(signals=[]))
    _benign_url_env(monkeypatch, tmp_path, [], upload=up)  # body unknown (no signals)
    report = await Pipeline(_config(never_upload=False)).run(_url_request(allow_cloud_upload=True))
    assert up.upload_calls == 1
    assert report.uploaded_to == "virustotal" and report.uploaded_at == _SENT_AT


@pytest.mark.asyncio
async def test_url_body_lock_closed_no_upload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Point 19: lock closed -> zero upload requests in the URL branch, not incomplete."""
    up = _BodyUpload(_outcome())
    _benign_url_env(monkeypatch, tmp_path, [], upload=up)
    report = await Pipeline(_config(never_upload=True)).run(_url_request(allow_cloud_upload=True))
    assert up.upload_calls == 0
    assert "cloud_upload" not in report.unavailable_sources and report.incomplete is False


@pytest.mark.asyncio
async def test_url_body_upload_blocked_when_reputation_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Point 20: consent given but body reputation failed -> no upload, INFO explains."""
    up = _BodyUpload(_outcome())
    _benign_url_env(monkeypatch, tmp_path, [], hash_raises=True, upload=up)
    report = await Pipeline(_config(never_upload=False)).run(_url_request(allow_cloud_upload=True))
    assert up.upload_calls == 0
    skip = next(s for s in report.signals if s.source == "cloud_upload")
    assert "could not verify" in skip.title_en
    assert report.uploaded_to is None


@pytest.mark.parametrize(
    "outcome",
    [
        _outcome(),  # success
        _outcome(availability=Availability.ERROR, detail="cancelled"),  # cancel after send
        _outcome(sent=False, availability=Availability.ERROR, detail="upload error"),  # error
        _outcome(availability=Availability.ERROR, detail="result not received"),  # timeout
    ],
    ids=["success", "cancel", "error", "timeout"],
)
@pytest.mark.asyncio
async def test_url_temp_dir_removed_after_every_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcome: UploadOutcome
) -> None:
    """Point 21: the temp folder is removed after success, cancel, error, or timeout."""
    up = _BodyUpload(outcome)
    created = _benign_url_env(monkeypatch, tmp_path, [], upload=up)
    await Pipeline(_config(never_upload=False)).run(_url_request(allow_cloud_upload=True))
    assert created and all(not d.exists() for d in created), "download temp dir was not cleaned up"


# --------------------------------------------------------------------------- #
# F0 hardening: the gate keys off named constants, not string literals
# --------------------------------------------------------------------------- #
def _benign_url_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """Benign network stubs for a URL scan with no download (keyless URL providers)."""
    monkeypatch.setattr(config_mod, "get_api_key", lambda _pid: None)

    async def old_age(_domain: str, *, timeout_s: float = 15.0) -> int:
        return 400

    async def good_tls(_host: str, port: int = 443, *, timeout_s: float = 15.0) -> TlsResult:
        return TlsResult(valid=True, host_match=True)

    async def plain_inspect(url: str, **_kw: object) -> InspectResult:
        return InspectResult(
            final_url=url, redirect_chain=[url], registrable_changed=False, http_status=200
        )

    monkeypatch.setattr(pipeline_mod, "domain_age_days", old_age)
    monkeypatch.setattr(pipeline_mod, "inspect_tls", good_tls)
    monkeypatch.setattr(pipeline_mod, "inspect_url", plain_inspect)


@pytest.mark.asyncio
async def test_url_without_download_offers_no_upload(monkeypatch: pytest.MonkeyPatch) -> None:
    """Points 9-11: a link with no downloaded body offers no upload, keyed by constants.

    URL reputation stages carry STAGE_URL_REPUTATION; only a downloaded-body hash uses
    STAGE_REPUTATION. With no download there is no STAGE_REPUTATION stage, so the gate's
    precondition is unmet and upload_could_help is False. Asserting via the constants
    (not literals) means renaming a key for UI text ripples into this test, not silence.
    """
    _benign_url_only(monkeypatch)
    request = ScanRequest(
        target_kind=TargetKind.URL, url="https://good-site.com/page", allow_network=True
    )
    report = await Pipeline(AppConfig.load()).run(request)
    assert report.upload_could_help is False
    titles = {s.title_key for s in report.stages}
    assert STAGE_URL_REPUTATION in titles  # URL reputation ran (skipped, keyless)
    assert STAGE_REPUTATION not in titles  # no body-hash stage exists to satisfy the gate


# --------------------------------------------------------------------------- #
# F0 privacy: the body's SHA-256 leaves only with the network on
# --------------------------------------------------------------------------- #
@respx.mock
@pytest.mark.asyncio
async def test_no_network_sends_nothing_for_url_with_download(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Point 13: with the network off, the body is not even downloaded -- zero requests."""
    _benign_url_env(monkeypatch, tmp_path, [])  # download/providers stubbed but unused offline
    request = ScanRequest(
        target_kind=TargetKind.URL,
        url="https://good-site.com/file",
        allow_network=False,
        allow_download=True,
    )
    await Pipeline(_config(never_upload=False)).run(request)
    assert respx.calls.call_count == 0  # nothing left the machine, body SHA-256 included


@pytest.mark.asyncio
async def test_only_send_hashes_does_not_block_body_reputation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Point 14: 'only send hashes' is about full URLs, not hashes -- body reputation runs."""
    _benign_url_env(monkeypatch, tmp_path, [])  # body unknown; reputation still runs
    config = _config(never_upload=False)
    config.only_send_hashes = True
    report = await Pipeline(config).run(_url_request())
    # The body's hash reputation stage ran (STAGE_REPUTATION), unaffected by only-hashes.
    body_rep = [s for s in report.stages if s.title_key == STAGE_REPUTATION]
    assert body_rep and all(s.status is StageStatus.DONE for s in body_rep)
