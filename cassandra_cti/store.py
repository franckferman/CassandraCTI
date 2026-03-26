# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# store.py
from __future__ import annotations
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import List, Tuple

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


class Store:
    def __init__(self, path: str):
        self.path = path
        self._init()

    def _init(self):
        with sqlite3.connect(self.path) as db:
            db.executescript(SCHEMA)

    def upsert_event(self, eid: str, source: str, url: str | None, title: str, summary: str, published_at: str | None):
        now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        with sqlite3.connect(self.path) as db:
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
        with sqlite3.connect(self.path) as db:
            cur = db.execute("SELECT 1 FROM deliveries WHERE event_id=? AND transport_id=? AND status='ok' LIMIT 1", (eid, tid))
            return cur.fetchone() is not None

    def mark_delivery(self, eid: str, tid: str, status: str, err: str | None = None):
        now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        with sqlite3.connect(self.path) as db:
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
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM events WHERE last_seen_at < ?", (cutoff,))

    def unsent_since(self, transport_id: str, since_iso: str) -> List[Tuple[str, str, str, str, str, str]]:
        with sqlite3.connect(self.path) as db:
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
        with sqlite3.connect(self.path) as db:
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
