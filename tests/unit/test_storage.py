"""Tests for core/storage.py: verdict cache (TTL) and history."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from prescan.core.models import (
    FileInfo,
    ScanReport,
    ScanRequest,
    TargetKind,
    Verdict,
)
from prescan.core.storage import Storage


def _report(sha: str, verdict: Verdict = Verdict.UNKNOWN) -> ScanReport:
    now = datetime.now(UTC)
    file_info = FileInfo(
        path=Path("/tmp/x"),
        name="x",
        size=1,
        declared_extension="",
        detected_type="data",
        detected_mime="application/octet-stream",
        md5="0" * 32,
        sha1="0" * 40,
        sha256=sha,
    )
    return ScanReport(
        scan_id="s",
        app_version="0.0.0",
        request=ScanRequest(target_kind=TargetKind.FILE, file_path=Path("/tmp/x")),
        started_at=now,
        finished_at=now,
        duration_s=0.0,
        file=file_info,
        verdict=verdict,
        risk_score=0,
        verdict_reason_key="verdict.unknown",
        verdict_reason_en="r",
    )


def test_cache_round_trip_sets_from_cache(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "db.sqlite")
    sha = "a" * 64
    storage.put_cache(_report(sha))
    cached = storage.get_cached(sha, ttl_days=7)
    assert cached is not None
    assert cached.from_cache is True
    assert cached.file is not None
    assert cached.file.sha256 == sha


def test_cache_miss_returns_none(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "db.sqlite")
    assert storage.get_cached("f" * 64, ttl_days=7) is None


def test_cache_respects_ttl(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "db.sqlite")
    sha = "b" * 64
    storage.put_cache(_report(sha))
    # ttl_days=0 makes any stored entry already stale.
    assert storage.get_cached(sha, ttl_days=0) is None


def test_history_records_and_lists(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "db.sqlite")
    storage.add_history(_report("a" * 64, Verdict.DANGEROUS))
    storage.add_history(_report("b" * 64, Verdict.SAFE))
    rows = storage.list_history(limit=10)
    assert len(rows) == 2
    assert rows[0].verdict == "safe"  # newest first


def test_clear_history(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "db.sqlite")
    storage.add_history(_report("a" * 64))
    storage.clear_history()
    assert storage.list_history() == []


def test_migration_adds_sha256_without_dropping_rows(tmp_path: Path) -> None:
    """A pre-sha256 history table must be migrated in place, never dropped."""
    import sqlite3

    db = tmp_path / "db.sqlite"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE history ("
        "id INTEGER PRIMARY KEY, scan_id VARCHAR, target VARCHAR, "
        "target_kind VARCHAR, verdict VARCHAR, risk_score INTEGER, "
        "sources VARCHAR, created_at DATETIME)"
    )
    conn.execute(
        "INSERT INTO history (scan_id, target, target_kind, verdict, risk_score, "
        "sources, created_at) VALUES ('s', '/tmp/old', 'file', 'safe', 0, '', "
        "'2026-08-01 00:00:00')"
    )
    conn.commit()
    conn.close()

    storage = Storage(db)  # runs _migrate()

    rows = storage.list_history(limit=10)
    assert len(rows) == 1  # existing record preserved, not dropped
    assert rows[0].target == "/tmp/old"
    # New scans still work against the migrated table.
    storage.add_history(_report("c" * 64, Verdict.DANGEROUS))
    assert len(storage.list_history(limit=10)) == 2
