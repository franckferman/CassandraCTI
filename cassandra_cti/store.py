# store.py
from __future__ import annotations
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  url TEXT,
  title TEXT,
  summary TEXT,
  published_at TEXT,
  first_seen_at TEXT NOT NULL,
  last_seen_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_events_source ON events(source);

CREATE TABLE IF NOT EXISTS deliveries (
  event_id TEXT NOT NULL,
  transport_id TEXT NOT NULL,
  delivered_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('ok','failed')),
  attempts INTEGER NOT NULL DEFAULT 1,
  last_error TEXT,
  PRIMARY KEY (event_id, transport_id)
);

CREATE INDEX IF NOT EXISTS ix_deliveries_transport ON deliveries(transport_id);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class Store:
    def __init__(self, path: str):
        self.path = path
        self._init()

    # `with closing(conn) as db, db:` closes the connection (no leak) AND
    # commits via the connection's own context manager. Read-only helpers use
    # `with closing(conn) as db:` (close only).
    def _connect(self):
        return sqlite3.connect(self.path)

    def _init(self):
        with closing(self._connect()) as db, db:
            db.executescript(SCHEMA)

    def upsert_event(self, eid: str, source: str, url: str | None, title: str, summary: str, published_at: str | None):
        now = _now()
        with closing(self._connect()) as db, db:
            db.execute(
                """
                INSERT INTO events(id, source, url, title, summary, published_at, first_seen_at, last_seen_at)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                  source=excluded.source,
                  url=excluded.url,
                  title=excluded.title,
                  summary=excluded.summary,
                  published_at=COALESCE(excluded.published_at, events.published_at),
                  last_seen_at=excluded.last_seen_at
                """,
                (eid, source, url, title, summary, published_at, now, now)
            )

    def delivered_ok(self, eid: str, tid: str) -> bool:
        with closing(self._connect()) as db:
            cur = db.execute(
                "SELECT 1 FROM deliveries WHERE event_id=? AND transport_id=? AND status='ok' LIMIT 1",
                (eid, tid))
            return cur.fetchone() is not None

    def mark_delivery(self, eid: str, tid: str, status: str, err: str | None = None):
        now = _now()
        with closing(self._connect()) as db, db:
            db.execute(
                """
                INSERT INTO deliveries(event_id, transport_id, delivered_at, status, attempts, last_error)
                VALUES(?, ?, ?, ?, 1, ?)
                ON CONFLICT(event_id, transport_id) DO UPDATE SET
                  delivered_at=excluded.delivered_at,
                  status=excluded.status,
                  attempts=deliveries.attempts+1,
                  last_error=excluded.last_error
                """,
                (eid, tid, now, status, err)
            )

    def purge_ttl(self, days: int):
        cutoff = (datetime.now(timezone.utc) - timedelta(days=int(days))).isoformat(timespec="seconds").replace("+00:00", "Z")
        with closing(self._connect()) as db, db:
            # Cascade to deliveries first so purged events don't leave orphaned
            # delivery rows (which would look "already delivered" if re-seen).
            db.execute(
                "DELETE FROM deliveries WHERE event_id IN (SELECT id FROM events WHERE last_seen_at < ?)",
                (cutoff,))
            db.execute("DELETE FROM events WHERE last_seen_at < ?", (cutoff,))

    def recent_events(self, limit: int = 200, source: str | None = None, q: str | None = None) -> List[Dict[str, Any]]:
        """Most recent events first — read-only, used by the web dashboard."""
        sql = "SELECT id, source, url, title, summary, published_at, first_seen_at FROM events"
        where, params = [], []
        if source:
            where.append("source = ?")
            params.append(source)
        if q:
            where.append("(title LIKE ? OR summary LIKE ?)")
            params.extend([f"%{q}%", f"%{q}%"])
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY COALESCE(published_at, first_seen_at) DESC LIMIT ?"
        params.append(int(limit))
        with closing(self._connect()) as db:
            cur = db.execute(sql, params)
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def stats(self) -> Dict[str, Any]:
        """Aggregate counters for the web dashboard — read-only."""
        with closing(self._connect()) as db:
            total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            per_source = dict(db.execute(
                "SELECT source, COUNT(*) FROM events GROUP BY source ORDER BY COUNT(*) DESC").fetchall())
            latest = db.execute(
                "SELECT MAX(COALESCE(published_at, first_seen_at)) FROM events").fetchone()[0]
            return {"total": total, "per_source": per_source, "latest": latest}

    def unsent_since(self, transport_id: str, since_iso: str) -> List[Tuple[str, str, str, str, str, str]]:
        with closing(self._connect()) as db:
            cur = db.execute(
                """
                SELECT id, source, url, title, summary, published_at
                FROM events e
                WHERE (published_at IS NULL OR published_at >= ?)
                AND NOT EXISTS (
                  SELECT 1 FROM deliveries d WHERE d.event_id = e.id AND d.transport_id = ? AND d.status='ok'
                )
                ORDER BY COALESCE(published_at, first_seen_at) ASC
                """,
                (since_iso, transport_id)
            )
            return cur.fetchall()

    def clear_seen(self, source_prefix: str | None, before_iso: str | None, since_iso: str | None = None):
        with closing(self._connect()) as db, db:
            if source_prefix and before_iso:
                ids = [r[0] for r in db.execute("SELECT id FROM events WHERE source LIKE ? AND last_seen_at < ?", (f"{source_prefix}%", before_iso)).fetchall()]
            elif source_prefix and since_iso:
                ids = [r[0] for r in db.execute("SELECT id FROM events WHERE source LIKE ? AND last_seen_at > ?", (f"{source_prefix}%", since_iso)).fetchall()]
            elif source_prefix:
                ids = [r[0] for r in db.execute("SELECT id FROM events WHERE source LIKE ?", (f"{source_prefix}%",)).fetchall()]
            elif before_iso:
                ids = [r[0] for r in db.execute("SELECT id FROM events WHERE last_seen_at < ?", (before_iso,)).fetchall()]
            elif since_iso:
                ids = [r[0] for r in db.execute("SELECT id FROM events WHERE last_seen_at > ?", (since_iso,)).fetchall()]
            else:
                ids = []
            if ids:
                db.executemany("DELETE FROM deliveries WHERE event_id=?", [(i,) for i in ids])
                db.executemany("DELETE FROM events WHERE id=?", [(i,) for i in ids])
