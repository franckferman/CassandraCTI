from cassandra_cti.store import Store


def test_delivery_is_tracked_per_transport(tmp_path):
    s = Store(str(tmp_path / "s.db"))
    s.upsert_event("e1", "rss:X", "https://x/1", "Title", "sum", None)
    assert s.delivered_ok("e1", "t1") is False
    s.mark_delivery("e1", "t1", "ok")
    assert s.delivered_ok("e1", "t1") is True
    # a different transport has NOT received it
    assert s.delivered_ok("e1", "t2") is False


def test_clear_seen_by_prefix_removes_event_and_delivery(tmp_path):
    s = Store(str(tmp_path / "s.db"))
    s.upsert_event("e1", "rss:A", "u1", "t", "", None)
    s.upsert_event("e2", "rss:B", "u2", "t", "", None)
    s.mark_delivery("e1", "t1", "ok")
    s.clear_seen("rss:A", None, None)
    assert s.delivered_ok("e1", "t1") is False   # e1 wiped
    assert s.delivered_ok("e2", "t1") is False   # e2 kept, just never delivered
