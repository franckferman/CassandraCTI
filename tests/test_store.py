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


def test_cve_correlations_cross_source(tmp_path):
    s = Store(str(tmp_path / "c.db"))
    CVE = "CVE-2026-1234"
    # KEV: structured meta.cve (kind vuln).
    s.upsert_event("k1", "cisa.kev", "https://nvd/1234", f"{CVE}: FortiOS RCE",
                   "patch now", None, tags=["kev"], meta={"cve": CVE})
    # News: CVE only in the title text (kind rss).
    s.upsert_event("n1", "rss:BleepingComputer", "https://bc/x",
                   f"Hackers exploit {CVE} in the wild", "mass scanning", None,
                   tags=["news"], meta={})
    # Ransomware: CVE in the summary text (kind ransomware).
    s.upsert_event("r1", "ransomware.live", "https://rw/x", "ACME breached by qilin",
                   f"entry names {CVE} as the initial vector", None,
                   tags=["ransomware"], meta={})
    # Single-source CVE -> excluded (min_sources=2).
    s.upsert_event("k2", "cisa.kev", "https://nvd/9999", "CVE-2026-9999: minor",
                   "low", None, tags=["kev"], meta={"cve": "CVE-2026-9999"})

    cors = s.cve_correlations(min_sources=2)
    cves = {c["cve"] for c in cors}
    assert CVE in cves
    assert "CVE-2026-9999" not in cves
    top = next(c for c in cors if c["cve"] == CVE)
    assert set(top["kinds"]) == {"vuln", "rss", "ransomware"}
    assert top["count"] == 3
    assert len(top["sources"]) == 3
    assert top["titles"]                       # a few sample titles kept


def test_cve_correlations_sorted_by_breadth(tmp_path):
    s = Store(str(tmp_path / "c.db"))
    # Wide: 3 kinds mention CVE-2026-1001.
    s.upsert_event("a1", "cisa.kev", "u1", "CVE-2026-1001: x", "", None, meta={"cve": "CVE-2026-1001"})
    s.upsert_event("a2", "rss:news", "u2", "news on CVE-2026-1001", "", None, meta={})
    s.upsert_event("a3", "ransomware.live", "u3", "victim", "uses CVE-2026-1001", None, meta={})
    # Narrow: 2 news outlets mention CVE-2026-2002 (2 sources, 1 kind).
    s.upsert_event("b1", "rss:A", "u4", "CVE-2026-2002 covered", "", None, meta={})
    s.upsert_event("b2", "rss:B", "u5", "more on CVE-2026-2002", "", None, meta={})

    cors = s.cve_correlations(min_sources=2)
    assert cors[0]["cve"] == "CVE-2026-1001"       # widest breadth (3 kinds) first
    assert "CVE-2026-2002" in {c["cve"] for c in cors}   # multi-outlet still surfaced
