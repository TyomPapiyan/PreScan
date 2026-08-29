"""SQLAlchemy storage: verdict cache (by SHA-256, 7-day TTL) and scan history.

Synchronous SQLAlchemy 2.0 over SQLite. The pipeline calls these methods from a
worker thread (``asyncio.to_thread``) so the event loop never blocks (§9.9).
The cache stores the full serialised report keyed by SHA-256; a fresh hit short-
circuits the pipeline with ``from_cache=True`` (§6 stage 3).
"""

from __future__ import annotations

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
    created_at: Mapped[datetime] = mapped_column()


def _aware(dt: datetime) -> datetime:
    """Return a timezone-aware datetime (SQLite drops tzinfo on read)."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


class Storage:
    """SQLite-backed cache and history. Methods are synchronous."""

    def __init__(self, db_path: Path) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._engine = create_engine(f"sqlite:///{db_path}", future=True)
        Base.metadata.create_all(self._engine)

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
        with Session(self._engine) as session:
            session.add(
                HistoryEntry(
                    scan_id=report.scan_id,
                    target=target,
                    target_kind=report.request.target_kind.value,
                    verdict=report.verdict.value,
                    risk_score=report.risk_score,
                    sources=sources,
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
