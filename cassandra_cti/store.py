# store.py
from __future__ import annotations
import json
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
  last_seen_at  TEXT NOT NULL,
  tags TEXT,
  meta TEXT
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

CREATE TABLE IF NOT EXISTS briefings (
  name TEXT PRIMARY KEY,
  last_sent_at TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _kind(source: str) -> str:
    """Coarse category for a source id, mirroring the dashboard's client-side
    kind() so server aggregates and UI badges agree."""
    s = (source or "").lower()
    if "ransomware" in s:
        return "ransomware"
    if "red.flag" in s or "redflag" in s:
        return "redflag"
    if "cisa.kev" in s or s.startswith("kev"):
        return "vuln"
    if "abuse.ch" in s or s.startswith("ioc"):
        return "ioc"
    if s.startswith("rss:"):
        return "rss"
    return "other"


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
            # Migrate pre-existing DBs that predate the tags/meta columns.
            have = {r[1] for r in db.execute("PRAGMA table_info(events)").fetchall()}
            if "tags" not in have:
                db.execute("ALTER TABLE events ADD COLUMN tags TEXT")
            if "meta" not in have:
                db.execute("ALTER TABLE events ADD COLUMN meta TEXT")

    def upsert_event(self, eid: str, source: str, url: str | None, title: str, summary: str,
                     published_at: str | None, tags: List[str] | None = None,
                     meta: Dict[str, Any] | None = None):
        now = _now()
        tags_json = json.dumps(list(tags)) if tags else None
        meta_json = json.dumps(meta) if meta else None
        with closing(self._connect()) as db, db:
            db.execute(
                """
                INSERT INTO events(id, source, url, title, summary, published_at, first_seen_at, last_seen_at, tags, meta)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                  source=excluded.source,
                  url=excluded.url,
                  title=excluded.title,
                  summary=excluded.summary,
                  published_at=COALESCE(excluded.published_at, events.published_at),
                  last_seen_at=excluded.last_seen_at,
                  tags=COALESCE(excluded.tags, events.tags),
                  meta=COALESCE(excluded.meta, events.meta)
                """,
                (eid, source, url, title, summary, published_at, now, now, tags_json, meta_json)
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

    def recent_events(self, limit: int = 200, source: str | None = None, q: str | None = None,
                      source_like: str | None = None) -> List[Dict[str, Any]]:
        """Most recent events first. Read-only, used by the web dashboard.

        `source` matches exactly; `source_like` matches a prefix (e.g. 'rss:')
        so a category tab can pull every feed at once.
        """
        sql = "SELECT id, source, url, title, summary, published_at, first_seen_at, tags, meta FROM events"
        where, params = [], []
        if source:
            where.append("source = ?")
            params.append(source)
        if source_like:
            where.append("source LIKE ?")
            params.append(f"{source_like}%")
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
            out = []
            for row in cur.fetchall():
                d = dict(zip(cols, row))
                d["tags"] = json.loads(d["tags"]) if d.get("tags") else []
                d["meta"] = json.loads(d["meta"]) if d.get("meta") else {}
                out.append(d)
            return out

    def events_between(self, lo_iso: str, hi_iso: str, limit: int = 500) -> List[Dict[str, Any]]:
        """Events first seen in [lo, hi), newest first. This is the window a briefing
        summarizes. Keyed on first_seen_at (when WE ingested it) so a briefing
        reflects 'what came in since last time', not original publish dates."""
        with closing(self._connect()) as db:
            cur = db.execute(
                "SELECT id, source, url, title, summary, published_at, first_seen_at, tags, meta "
                "FROM events WHERE first_seen_at >= ? AND first_seen_at < ? "
                "ORDER BY first_seen_at DESC LIMIT ?",
                (lo_iso, hi_iso, int(limit)))
            cols = [c[0] for c in cur.description]
            out = []
            for row in cur.fetchall():
                d = dict(zip(cols, row))
                d["tags"] = json.loads(d["tags"]) if d.get("tags") else []
                d["meta"] = json.loads(d["meta"]) if d.get("meta") else {}
                out.append(d)
            return out

    def briefing_last_sent(self, name: str) -> str | None:
        with closing(self._connect()) as db:
            row = db.execute("SELECT last_sent_at FROM briefings WHERE name=?", (name,)).fetchone()
            return row[0] if row else None

    def mark_briefing_sent(self, name: str, when_iso: str):
        with closing(self._connect()) as db, db:
            db.execute(
                "INSERT INTO briefings(name, last_sent_at) VALUES(?, ?) "
                "ON CONFLICT(name) DO UPDATE SET last_sent_at=excluded.last_sent_at",
                (name, when_iso))

    def stats(self) -> Dict[str, Any]:
        """Aggregate counters for the web dashboard. Read-only.

        Returns totals, per-source and per-category breakdowns, per-source
        last-seen (source health), a 30-day daily and a 24-hour hourly activity
        series, current-vs-previous window deltas (24h / 7d / 30d), and delivery
        ('alerts sent') counters derived from the deliveries table.
        """
        now = datetime.now(timezone.utc)

        def iso(dt):
            return dt.isoformat(timespec="seconds").replace("+00:00", "Z")

        # `ts` is a fixed column expression (no user input) inlined into each
        # query as a literal so static analysers don't flag string-built SQL.
        with closing(self._connect()) as db:
            total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            per_source = dict(db.execute(
                "SELECT source, COUNT(*) FROM events GROUP BY source ORDER BY COUNT(*) DESC").fetchall())
            latest = db.execute(
                "SELECT MAX(COALESCE(published_at, first_seen_at)) FROM events").fetchone()[0]
            source_last = dict(db.execute(
                "SELECT source, MAX(COALESCE(published_at, first_seen_at)) FROM events "
                "GROUP BY source").fetchall())

            per_category: Dict[str, int] = {}
            for src, cnt in per_source.items():
                per_category[_kind(src)] = per_category.get(_kind(src), 0) + cnt

            def count_between(h_from, h_to):
                lo = iso(now - timedelta(hours=h_from))
                hi = iso(now - timedelta(hours=h_to)) if h_to else iso(now + timedelta(hours=1))
                return db.execute(
                    "SELECT COUNT(*) FROM events WHERE "
                    "COALESCE(published_at, first_seen_at) >= ? AND "
                    "COALESCE(published_at, first_seen_at) < ?", (lo, hi)).fetchone()[0]

            windows = {
                "24h": {"cur": count_between(24, 0), "prev": count_between(48, 24)},
                "7d": {"cur": count_between(168, 0), "prev": count_between(336, 168)},
                "30d": {"cur": count_between(720, 0), "prev": count_between(1440, 720)},
            }

            by_day = dict(db.execute(
                "SELECT substr(COALESCE(published_at, first_seen_at), 1, 10) d, COUNT(*) "
                "FROM events GROUP BY d").fetchall())
            today = now.date()
            activity = [{"date": (today - timedelta(days=i)).isoformat(),
                         "count": int(by_day.get((today - timedelta(days=i)).isoformat(), 0))}
                        for i in range(29, -1, -1)]

            by_hour = dict(db.execute(
                "SELECT substr(COALESCE(published_at, first_seen_at), 1, 13) h, COUNT(*) "
                "FROM events WHERE COALESCE(published_at, first_seen_at) >= ? GROUP BY h",
                (iso(now - timedelta(hours=24)),)).fetchall())
            activity_hourly = []
            for i in range(23, -1, -1):
                key = iso(now - timedelta(hours=i))[:13]
                activity_hourly.append({"hour": key, "count": int(by_hour.get(key, 0))})

            deliveries = {"sent_ok": 0, "failed": 0, "per_transport": {}}
            for tid, status, cnt in db.execute(
                    "SELECT transport_id, status, COUNT(*) FROM deliveries "
                    "GROUP BY transport_id, status").fetchall():
                if status == "ok":
                    deliveries["sent_ok"] += cnt
                elif status == "failed":
                    deliveries["failed"] += cnt
                deliveries["per_transport"].setdefault(tid, {})[status] = cnt

            return {
                "total": total,
                "per_source": per_source,
                "per_category": per_category,
                "source_last": source_last,
                "latest": latest,
                "last_24h": windows["24h"]["cur"],
                "windows": windows,
                "activity": activity,
                "activity_hourly": activity_hourly,
                "deliveries": deliveries,
            }

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
