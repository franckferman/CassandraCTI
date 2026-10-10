"""Store maintenance/query tests: upsert conflict, purge_ttl cascade,
unsent_since filtering/ordering, clear_seen branches, delivered_ok.

Rows whose timestamps must be controlled are seeded with direct sqlite3
writes so ``last_seen_at`` / ``published_at`` are exact and deterministic.
"""
import sqlite3

from cassandra_cti.store import Store


def _seed_event(path, eid, source, published_at, first_seen, last_seen,
                url="u", title="t", summary="s"):
    con = sqlite3.connect(path)
    with con:
        con.execute(
            """
            INSERT INTO events(id, source, url, title, summary,
                               published_at, first_seen_at, last_seen_at)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (eid, source, url, title, summary, published_at,
             first_seen, last_seen),
        )
    con.close()


def _row(path, eid):
    con = sqlite3.connect(path)
    cur = con.execute(
        """
        SELECT source, url, title, summary, published_at,
               first_seen_at, last_seen_at
        FROM events WHERE id=?
        """,
        (eid,),
    )
    r = cur.fetchone()
    con.close()
    return r


def _event_ids(path):
    con = sqlite3.connect(path)
    ids = {r[0] for r in con.execute("SELECT id FROM events").fetchall()}
    con.close()
    return ids


def _delivery_event_ids(path):
    con = sqlite3.connect(path)
    ids = {r[0] for r in con.execute(
        "SELECT event_id FROM deliveries").fetchall()}
    con.close()
    return ids


def test_upsert_conflict_updates_fields_and_coalesces_published(tmp_path):
    path = str(tmp_path / "s.db")
    s = Store(path)
    # Seed with an old first/last_seen and a concrete published_at.
    _seed_event(path, "e1", "rss:old", "2021-05-05T00:00:00Z",
                "2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z",
                url="old-url", title="old-title", summary="old-sum")

    # Re-upsert the same id with published_at=None.
    s.upsert_event("e1", "rss:new", "new-url", "new-title", "new-sum", None)

    (source, url, title, summary, published_at,
     first_seen, last_seen) = _row(path, "e1")
    # Mutable fields are overwritten from the new values.
    assert source == "rss:new"
    assert url == "new-url"
    assert title == "new-title"
    assert summary == "new-sum"
    # COALESCE keeps the existing published_at because the new one is None.
    assert published_at == "2021-05-05T00:00:00Z"
    # first_seen_at is never touched on conflict.
    assert first_seen == "2020-01-01T00:00:00Z"
    # last_seen_at advances past the seeded value.
    assert last_seen > "2020-01-01T00:00:00Z"


def test_upsert_conflict_overwrites_published_when_not_null(tmp_path):
    path = str(tmp_path / "s.db")
    s = Store(path)
    _seed_event(path, "e1", "rss", "2021-05-05T00:00:00Z",
                "2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z")
    s.upsert_event("e1", "rss", "u", "t", "s", "2022-09-09T00:00:00Z")
    published_at = _row(path, "e1")[4]
    assert published_at == "2022-09-09T00:00:00Z"


def test_purge_ttl_removes_stale_and_cascades_deliveries(tmp_path):
    path = str(tmp_path / "s.db")
    s = Store(path)
    # Stale: last_seen far in the past. Fresh: far in the future so it is
    # always newer than (now - days), regardless of the current date.
    _seed_event(path, "stale", "rss:A", None,
                "2000-01-01T00:00:00Z", "2000-01-01T00:00:00Z")
    _seed_event(path, "fresh", "rss:B", None,
                "2999-01-01T00:00:00Z", "2999-01-01T00:00:00Z")
    s.mark_delivery("stale", "t1", "ok")
    s.mark_delivery("fresh", "t1", "ok")

    s.purge_ttl(30)

    # Stale event gone, fresh kept.
    assert _event_ids(path) == {"fresh"}
    # The stale delivery was cascaded; only the fresh delivery remains.
    assert _delivery_event_ids(path) == {"fresh"}


def test_unsent_since_filters_and_orders(tmp_path):
    path = str(tmp_path / "s.db")
    s = Store(path)
    since = "2023-06-01T00:00:00Z"
    # Before the cutoff -> excluded.
    _seed_event(path, "e_before", "rss", "2023-01-01T00:00:00Z",
                "2023-01-01T00:00:00Z", "2023-01-01T00:00:00Z")
    # NULL published_at -> always included; ordered by first_seen_at.
    _seed_event(path, "e_null", "rss", None,
                "2023-07-15T00:00:00Z", "2023-07-15T00:00:00Z")
    _seed_event(path, "e_after", "rss", "2023-08-01T00:00:00Z",
                "2023-08-01T00:00:00Z", "2023-08-01T00:00:00Z")
    _seed_event(path, "e_ok", "rss", "2023-09-01T00:00:00Z",
                "2023-09-01T00:00:00Z", "2023-09-01T00:00:00Z")
    _seed_event(path, "e_failed", "rss", "2023-10-01T00:00:00Z",
                "2023-10-01T00:00:00Z", "2023-10-01T00:00:00Z")
    s.mark_delivery("e_ok", "t1", "ok")
    s.mark_delivery("e_failed", "t1", "failed")

    # For t1: e_before excluded (too old), e_ok excluded ('ok' delivery),
    # e_failed still included (delivery not 'ok'), ordered ascending.
    ids_t1 = [r[0] for r in s.unsent_since("t1", since)]
    assert ids_t1 == ["e_null", "e_after", "e_failed"]

    # For a different transport nothing is 'ok', so e_ok reappears.
    ids_t2 = [r[0] for r in s.unsent_since("t2", since)]
    assert ids_t2 == ["e_null", "e_after", "e_ok", "e_failed"]


def _seed_clear_fixture(path):
    s = Store(path)
    _seed_event(path, "e1", "rss:A", None,
                "2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z")
    _seed_event(path, "e2", "rss:A", None,
                "2025-01-01T00:00:00Z", "2025-01-01T00:00:00Z")
    _seed_event(path, "e3", "other", None,
                "2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z")
    return s


def test_clear_seen_prefix_and_before(tmp_path):
    path = str(tmp_path / "s.db")
    s = _seed_clear_fixture(path)
    # source LIKE rss:A% AND last_seen_at < cutoff -> only the old e1.
    s.clear_seen("rss:A", "2023-01-01T00:00:00Z", None)
    assert _event_ids(path) == {"e2", "e3"}


def test_clear_seen_prefix_and_since(tmp_path):
    path = str(tmp_path / "s.db")
    s = _seed_clear_fixture(path)
    # source LIKE rss:A% AND last_seen_at > cutoff -> only the new e2.
    s.clear_seen("rss:A", None, "2023-01-01T00:00:00Z")
    assert _event_ids(path) == {"e1", "e3"}


def test_clear_seen_prefix_only(tmp_path):
    path = str(tmp_path / "s.db")
    s = _seed_clear_fixture(path)
    # All rss:A% events regardless of time.
    s.clear_seen("rss:A", None, None)
    assert _event_ids(path) == {"e3"}


def test_clear_seen_before_only(tmp_path):
    path = str(tmp_path / "s.db")
    s = _seed_clear_fixture(path)
    # last_seen_at < cutoff across every source.
    s.clear_seen(None, "2023-01-01T00:00:00Z", None)
    assert _event_ids(path) == {"e2"}


def test_clear_seen_since_only(tmp_path):
    path = str(tmp_path / "s.db")
    s = _seed_clear_fixture(path)
    # last_seen_at > cutoff across every source.
    s.clear_seen(None, None, "2023-01-01T00:00:00Z")
    assert _event_ids(path) == {"e1", "e3"}


def test_clear_seen_no_args_deletes_nothing(tmp_path):
    path = str(tmp_path / "s.db")
    s = _seed_clear_fixture(path)
    s.clear_seen(None, None, None)
    assert _event_ids(path) == {"e1", "e2", "e3"}


def test_delivered_ok_false_for_failed_delivery(tmp_path):
    path = str(tmp_path / "s.db")
    s = Store(path)
    s.upsert_event("e1", "rss", "u", "t", "s", None)
    s.mark_delivery("e1", "t1", "failed")
    assert s.delivered_ok("e1", "t1") is False
