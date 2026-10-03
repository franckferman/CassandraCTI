import asyncio

from cassandra_cti.sources.ransomware_stats import RansomwareStats

DATA = {"last_update": "2026-07-06T14:56:41.7+00:00",
        "stats": {"victims": 29431, "groups": 356, "press": 3768}}


def test_stats_skips_without_key():
    assert asyncio.run(RansomwareStats(api_key="").fetch()) == []


def test_stats_emits_one_daily_digest():
    evs = RansomwareStats(api_key="k")._normalize(DATA)
    assert len(evs) == 1
    ev = evs[0]
    assert "2026-07-06" in ev.title                 # per-day dedup identity
    assert "29431" in ev.summary and "356" in ev.summary and "3768" in ev.summary
    assert ev.tags == ["stats", "digest"]
    assert ev.published_at is not None
