"""SQLAlchemy storage: verdict cache (by SHA-256, 7-day TTL) and scan history.

Synchronous SQLAlchemy 2.0 over SQLite. The pipeline calls these methods from a
worker thread (``asyncio.to_thread``) so the event loop never blocks (§9.9).
The cache stores the full serialised report keyed by SHA-256; a fresh hit short-
circuits the pipeline with ``from_cache=True`` (§6 stage 3).
"""

from __future__ import annotations

import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import structlog
from sqlalchemy import String, Text, create_engine, delete, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from prescan.core.models import ScanReport
from prescan.core.report import from_json, to_json

log = structlog.get_logger(__name__)


class Base(DeclarativeBase):
    """Declarative base for storage tables."""


class CacheEntry(Base):
    __tablename__ = "verdict_cache"

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    report_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column()


class HistoryEntry(Base):
    __tablename__ = "history"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(32))
    target: Mapped[str] = mapped_column(Text)
    target_kind: Mapped[str] = mapped_column(String(8))
    verdict: Mapped[str] = mapped_column(String(16))
    risk_score: Mapped[int] = mapped_column()
    sources: Mapped[str] = mapped_column(Text, default="")
    sha256: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column()


def _aware(dt: datetime) -> datetime:
    """Return a timezone-aware datetime (SQLite drops tzinfo on read)."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


class Storage:
    """SQLite-backed cache and history. Methods are synchronous."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._engine = create_engine(f"sqlite:///{db_path}", future=True)
        self._migrate()
        Base.metadata.create_all(self._engine)

    def _pending_migrations(self) -> list[str]:
        """Additive-only migration statements needed to update the schema.

        DROP TABLE / DROP COLUMN are forbidden here (CLAUDE.md migration rule):
        a real incident wiped user history. Only ADD COLUMN / CREATE IF NOT EXISTS.
        """
        from sqlalchemy import inspect

        inspector = inspect(self._engine)
        stmts: list[str] = []
        if "history" in inspector.get_table_names():
            columns = {c["name"] for c in inspector.get_columns("history")}
            if "sha256" not in columns:
                stmts.append("ALTER TABLE history ADD COLUMN sha256 VARCHAR(64) DEFAULT ''")
        return stmts

    def _migrate(self) -> None:
        """Apply pending additive migrations, backing up the DB file first.

        A dated copy (``<db>.bak-<stamp>``) is made before any schema change and
        removed only on success; a failed migration leaves the backup in place.
        """
        from sqlalchemy import text

        statements = self._pending_migrations()
        if not statements:
            return

        backup = self._backup_db()
        try:
            with self._engine.begin() as conn:
                for sql in statements:
                    conn.execute(text(sql))
        except Exception:
            log.error("db_migration_failed", backup=str(backup) if backup else None)
            raise
        if backup is not None:
            backup.unlink(missing_ok=True)
            log.info("db_migration_ok", removed_backup=str(backup))

    def _backup_db(self) -> Path | None:
        """Copy the DB file next to itself before a migration (None if empty/new)."""
        if not self._db_path.exists() or self._db_path.stat().st_size == 0:
            return None
        self._engine.dispose()  # release the pooled connection before copying
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        backup = self._db_path.with_name(f"{self._db_path.name}.bak-{stamp}")
        shutil.copy2(self._db_path, backup)
        log.info("db_backup_created", path=str(backup))
        return backup

    # ---- cache (§6 stage 3) -------------------------------------------- #
    def get_cached(self, sha256: str, *, ttl_days: int) -> ScanReport | None:
        """Return a cached report if present and fresher than ttl_days."""
        with Session(self._engine) as session:
            entry = session.get(CacheEntry, sha256)
            if entry is None:
                return None
            age = datetime.now(UTC) - _aware(entry.created_at)
            if age > timedelta(days=ttl_days):
                return None
            report = from_json(entry.report_json)
            return report.model_copy(update={"from_cache": True})

    def get_report(self, sha256: str) -> ScanReport | None:
        """Return the cached report for a hash regardless of TTL (history view)."""
        with Session(self._engine) as session:
            entry = session.get(CacheEntry, sha256)
            return from_json(entry.report_json) if entry is not None else None

    def put_cache(self, report: ScanReport) -> None:
        """Store or refresh a report in the cache keyed by its SHA-256."""
        if report.file is None:
            return
        sha256 = report.file.sha256
        with Session(self._engine) as session:
            entry = session.get(CacheEntry, sha256)
            payload = to_json(report.model_copy(update={"from_cache": False}))
            if entry is None:
                session.add(
                    CacheEntry(sha256=sha256, report_json=payload, created_at=datetime.now(UTC))
                )
            else:
                entry.report_json = payload
                entry.created_at = datetime.now(UTC)
            session.commit()

    # ---- history ------------------------------------------------------- #
    def add_history(self, report: ScanReport) -> None:
        """Append a scan to the history table."""
        target = report.file.name if report.file else (report.url.original if report.url else "")
        sources = ",".join(sorted({s.source for s in report.signals}))
        sha256 = report.file.sha256 if report.file else ""
        with Session(self._engine) as session:
            session.add(
                HistoryEntry(
                    scan_id=report.scan_id,
                    target=target,
                    target_kind=report.request.target_kind.value,
                    verdict=report.verdict.value,
                    risk_score=report.risk_score,
                    sources=sources,
                    sha256=sha256,
                    created_at=report.finished_at,
                )
            )
            session.commit()

    def list_history(self, *, limit: int = 50) -> list[HistoryEntry]:
        """Return the most recent history entries, newest first."""
        with Session(self._engine) as session:
            stmt = select(HistoryEntry).order_by(HistoryEntry.id.desc()).limit(limit)
            return list(session.scalars(stmt).all())

    def clear_history(self) -> None:
        """Delete every history row."""
        with Session(self._engine) as session:
            session.execute(delete(HistoryEntry))
            session.commit()

    def purge_expired_cache(self, *, ttl_days: int) -> int:
        """Delete cache entries older than ttl_days. Returns the count removed."""
        cutoff = datetime.now(UTC) - timedelta(days=ttl_days)
        with Session(self._engine) as session:
            rows = list(session.scalars(select(CacheEntry)).all())
            removed = 0
            for row in rows:
                if _aware(row.created_at) < cutoff:
                    session.delete(row)
                    removed += 1
            session.commit()
            return removed
