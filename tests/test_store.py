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


def test_briefing_outputs_history_order_and_filter(tmp_path):
    s = Store(str(tmp_path / "s.db"))
    # Empty to start.
    assert s.recent_briefings() == []
    s.save_briefing_output("cve-weekly", "CVE Top 10", "body-1", item_count=12, period_label="7d")
    s.save_briefing_output("ransomware", "RW Top 10", "body-2", item_count=8, period_label="24h")
    s.save_briefing_output("cve-weekly", "CVE Top 10", "body-3", item_count=15, period_label="7d")

    rows = s.recent_briefings()
    assert [r["body"] for r in rows] == ["body-3", "body-2", "body-1"]   # newest first
    r0 = rows[0]
    assert r0["name"] == "cve-weekly" and r0["title"] == "CVE Top 10"
    assert r0["item_count"] == 15 and r0["period_label"] == "7d" and r0["created_at"]

    # Filter by name.
    only_cve = s.recent_briefings(name="cve-weekly")
    assert [r["body"] for r in only_cve] == ["body-3", "body-1"]
    # Limit caps the rows.
    assert len(s.recent_briefings(limit=1)) == 1


def test_briefing_outputs_survive_reopen(tmp_path):
    db = str(tmp_path / "s.db")
    Store(db).save_briefing_output("x", "T", "persisted", item_count=1, period_label="24h")
    # A fresh Store on the same file (the dashboard opens its own) sees it.
    assert Store(db).recent_briefings()[0]["body"] == "persisted"
