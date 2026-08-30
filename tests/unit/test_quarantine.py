"""Tests for core/quarantine.py: AES-zip storage, restore, listing."""

from __future__ import annotations

import stat
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
import pyzipper

from prescan.core import quarantine as q
from prescan.core.models import (
    FileInfo,
    ScanReport,
    ScanRequest,
    TargetKind,
    Verdict,
)


@pytest.fixture(autouse=True)
def _qdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    store = tmp_path / "quarantine"
    store.mkdir()
    monkeypatch.setattr(q, "_quarantine_dir", lambda: store)
    return store


def _report(sha: str, name: str) -> ScanReport:
    now = datetime.now(UTC)
    return ScanReport(
        scan_id="s",
        app_version="0.0.0",
        request=ScanRequest(target_kind=TargetKind.FILE, file_path=Path("/tmp") / name),
        started_at=now,
        finished_at=now,
        duration_s=0.0,
        file=FileInfo(
            path=Path("/tmp") / name,
            name=name,
            size=3,
            declared_extension=".exe",
            detected_type="PE32",
            detected_mime="application/x-dosexec",
            md5="0" * 32,
            sha1="0" * 40,
            sha256=sha,
        ),
        verdict=Verdict.DANGEROUS,
        risk_score=100,
        verdict_reason_key="verdict.dangerous",
        verdict_reason_en="bad",
    )


def test_quarantine_moves_file_into_aes_zip(tmp_path: Path) -> None:
    sample = tmp_path / "evil.exe"
    sample.write_bytes(b"MZ payload")
    archive = q.quarantine(sample, _report("a" * 64, "evil.exe"))

    assert archive.exists()
    assert not sample.exists()  # moved, not copied
    if sys.platform != "win32":
        assert stat.S_IMODE(archive.stat().st_mode) == 0o600
    # Encrypted: the password "infected" is required to read the entry.
    with pyzipper.AESZipFile(archive) as zf:
        zf.setpassword(b"infected")
        assert zf.read("evil.exe") == b"MZ payload"


def test_wrong_password_cannot_read(tmp_path: Path) -> None:
    sample = tmp_path / "evil.exe"
    sample.write_bytes(b"MZ payload")
    archive = q.quarantine(sample, _report("b" * 64, "evil.exe"))
    with pyzipper.AESZipFile(archive) as zf, pytest.raises(RuntimeError):
        zf.read("evil.exe")  # no password set -> fails


def test_restore_returns_original_without_exec_bit(tmp_path: Path) -> None:
    sample = tmp_path / "evil.exe"
    sample.write_bytes(b"MZ payload")
    q.quarantine(sample, _report("c" * 64, "evil.exe"))

    dest = tmp_path / "restored"
    dest.mkdir()
    restored = q.restore("c" * 64, dest)
    assert restored.read_bytes() == b"MZ payload"
    if sys.platform != "win32":
        assert not (restored.stat().st_mode & 0o111)  # no executable bit


def test_list_and_purge(tmp_path: Path) -> None:
    sample = tmp_path / "evil.exe"
    sample.write_bytes(b"MZ payload")
    q.quarantine(sample, _report("d" * 64, "evil.exe"))

    entries = q.list_entries()
    assert len(entries) == 1
    assert entries[0].original_name == "evil.exe"
    assert entries[0].verdict == "dangerous"

    q.purge("d" * 64)
    assert q.list_entries() == []


def test_restore_missing_entry_raises() -> None:
    with pytest.raises(q.QuarantineError):
        q.restore("f" * 64, Path("/tmp"))
