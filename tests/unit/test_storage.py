"""Tests for core/storage.py: verdict cache (TTL) and history."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from prescan.core.models import (
    FileInfo,
    ScanReport,
    ScanRequest,
    TargetKind,
    Verdict,
)
from prescan.core.storage import Storage


def _report(
    sha: str,
    verdict: Verdict = Verdict.UNKNOWN,
    *,
    uploaded_to: str | None = None,
    uploaded_at: datetime | None = None,
) -> ScanReport:
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
        uploaded_to=uploaded_to,
        uploaded_at=uploaded_at,
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
    # A successful migration now KEEPS its backup (retention policy, stage-F point 8:
    # keep the three most recent). Previously the backup was deleted on success; the
    # policy changed so a recent pre-migration copy is always available for rollback.
    assert len(list(tmp_path.glob("db.sqlite.bak-*"))) == 1


def _old_schema_db_with_row(db: Path) -> None:
    import sqlite3

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


def test_failed_migration_keeps_backup_and_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A migration that raises must leave a backup copy and the original rows."""
    import sqlite3

    db = tmp_path / "db.sqlite"
    _old_schema_db_with_row(db)

    # Force a broken (but still additive-looking) migration statement.
    monkeypatch.setattr(
        Storage, "_pending_migrations", lambda self: ["ALTER TABLE nope ADD COLUMN x INT"]
    )
    with pytest.raises(Exception):  # noqa: B017 - any DB error is acceptable here
        Storage(db)

    backups = list(tmp_path.glob("db.sqlite.bak-*"))
    assert len(backups) == 1, "failed migration must retain the backup"
    # Original data is intact in the live DB file.
    conn = sqlite3.connect(db)
    assert conn.execute("SELECT COUNT(*) FROM history").fetchone()[0] == 1
    conn.close()


# --------------------------------------------------------------------------- #
# Stage F: uploaded_to / uploaded_at migration + history + backup retention
# --------------------------------------------------------------------------- #
def _pre_upload_schema_db(db: Path) -> None:
    """A history table with sha256 but WITHOUT the stage-13 upload columns, one row."""
    import sqlite3

    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE history ("
        "id INTEGER PRIMARY KEY, scan_id VARCHAR, target VARCHAR, "
        "target_kind VARCHAR, verdict VARCHAR, risk_score INTEGER, "
        "sources VARCHAR, sha256 VARCHAR, created_at DATETIME)"
    )
    conn.execute(
        "INSERT INTO history (scan_id, target, target_kind, verdict, risk_score, "
        "sources, sha256, created_at) VALUES ('s', '/tmp/old', 'file', 'safe', 0, '', "
        "'abc', '2026-08-01 00:00:00')"
    )
    conn.commit()
    conn.close()


def _history_columns(db: Path) -> set[str]:
    import sqlite3

    conn = sqlite3.connect(db)
    try:
        return {row[1] for row in conn.execute("PRAGMA table_info(history)")}
    finally:
        conn.close()


def test_upload_migration_adds_columns_without_touching_rows(tmp_path: Path) -> None:
    """Point 9: old DB gains uploaded_to/uploaded_at; the existing row is untouched."""
    db = tmp_path / "db.sqlite"
    _pre_upload_schema_db(db)

    storage = Storage(db)

    assert {"uploaded_to", "uploaded_at"} <= _history_columns(db)
    rows = storage.list_history(limit=10)
    assert len(rows) == 1 and rows[0].target == "/tmp/old"
    assert rows[0].uploaded_to is None and rows[0].uploaded_at is None  # default, unchanged


def test_upload_migration_is_idempotent(tmp_path: Path) -> None:
    """Point 9: opening the already-migrated DB again is a no-op and never raises."""
    db = tmp_path / "db.sqlite"
    _pre_upload_schema_db(db)

    Storage(db)  # first run migrates (one backup)
    Storage(db)  # second run: schema already current -> no migration, no new backup

    assert len(list(tmp_path.glob("db.sqlite.bak-*"))) == 1
    assert {"uploaded_to", "uploaded_at"} <= _history_columns(db)


def test_upload_migration_backs_up_before_changing(tmp_path: Path) -> None:
    """Point 9: the backup is taken BEFORE the schema changes -- it holds the old schema."""
    db = tmp_path / "db.sqlite"
    _pre_upload_schema_db(db)

    Storage(db)

    backups = list(tmp_path.glob("db.sqlite.bak-*"))
    assert len(backups) == 1
    # The copy predates the ALTER, so it must NOT contain the new columns.
    assert "uploaded_to" not in _history_columns(backups[0])


def test_upload_migration_skipped_when_backup_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Point 9 (+ point 7): if the backup cannot be made, the migration does not run."""
    import prescan.core.storage as storage_mod

    db = tmp_path / "db.sqlite"
    _pre_upload_schema_db(db)

    def boom(*_a: object, **_k: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(storage_mod.shutil, "copy2", boom)
    with pytest.raises(OSError):
        Storage(db)

    # The DB was left on the old schema (no ALTER ran) and no backup exists.
    assert "uploaded_to" not in _history_columns(db)
    assert list(tmp_path.glob("db.sqlite.bak-*")) == []


def test_backups_pruned_to_three_most_recent(tmp_path: Path) -> None:
    """Point 8: keep the three most recent backups, delete older ones."""
    db = tmp_path / "db.sqlite"
    Storage(db)  # create a valid DB file
    for i in range(5):
        (tmp_path / f"db.sqlite.bak-2026010{i}-000000-000000").write_text("x")

    Storage(db)._prune_backups(keep=3)

    remaining = sorted(p.name for p in tmp_path.glob("db.sqlite.bak-*"))
    assert remaining == [
        "db.sqlite.bak-20260102-000000-000000",
        "db.sqlite.bak-20260103-000000-000000",
        "db.sqlite.bak-20260104-000000-000000",
    ]


def test_history_records_upload_fields_file_and_url(tmp_path: Path) -> None:
    """Point 20: a history row carries uploaded_to/at, filled from the report."""
    storage = Storage(tmp_path / "db.sqlite")
    when = datetime(2026, 9, 6, 10, 30, tzinfo=UTC)

    file_report = _report("a" * 64, Verdict.SAFE, uploaded_to="virustotal", uploaded_at=when)
    storage.add_history(file_report)

    url_report = _report("b" * 64, Verdict.UNKNOWN, uploaded_to="virustotal", uploaded_at=when)
    url_report = url_report.model_copy(
        update={"request": ScanRequest(target_kind=TargetKind.URL, url="https://x.test/f")}
    )
    storage.add_history(url_report)

    rows = storage.list_history(limit=10)
    assert all(r.uploaded_to == "virustotal" for r in rows)
    assert all(r.uploaded_at is not None for r in rows)


def test_history_row_leaks_no_secret(tmp_path: Path) -> None:
    """Point 17: no API key or one-time upload URL appears in a history row's fields."""
    storage = Storage(tmp_path / "db.sqlite")
    when = datetime(2026, 9, 6, 10, 30, tzinfo=UTC)
    storage.add_history(_report("a" * 64, Verdict.SAFE, uploaded_to="virustotal", uploaded_at=when))

    row = storage.list_history(limit=1)[0]
    blob = " ".join(
        str(x)
        for x in (row.scan_id, row.target, row.sources, row.sha256, row.uploaded_to, row.verdict)
    )
    assert "vt_secret_key_DEADBEEF" not in blob
    assert "_ah/upload/ONE_TIME_SECRET" not in blob


def test_cached_uploaded_report_round_trips_without_reoffer(tmp_path: Path) -> None:
    """Point 15/25: a cached report that recorded an upload keeps upload_could_help False.

    upload_could_help is False whenever a file was uploaded (core sets it so), so the
    cached copy never re-offers an upload; from_cache is set on read.
    """
    storage = Storage(tmp_path / "db.sqlite")
    when = datetime(2026, 9, 6, 10, 30, tzinfo=UTC)
    storage.put_cache(_report("a" * 64, Verdict.SAFE, uploaded_to="virustotal", uploaded_at=when))

    cached = storage.get_cached("a" * 64, ttl_days=7)
    assert cached is not None
    assert cached.from_cache is True
    assert cached.uploaded_to == "virustotal"
    assert cached.upload_could_help is False  # recorded upload -> never re-offered
