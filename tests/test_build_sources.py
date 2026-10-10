import asyncio

from cassandra_cti.sources import build_sources
from cassandra_cti.sources.rss import RSS
from cassandra_cti.sources.ransomware_live import RansomwareLive
from cassandra_cti.sources.ransomware_press import RansomwarePress
from cassandra_cti.sources.ransomware_8k import Ransomware8K
from cassandra_cti.sources.ransomware_stats import RansomwareStats
from cassandra_cti.sources.redflag import RedFlagDomains


def _build(cfg):
    return asyncio.run(build_sources({"sources": cfg}))


def test_build_sources_enables_every_configured_source():
    srcs = _build({
        "rss": {"enabled": True, "feeds": [{"name": "X", "url": "http://x", "tags": ["t"]}]},
        "ransomware_live": {"enabled": True, "api_key": "k", "lookback_days": 5},
        "ransomware_press": {"enabled": True, "api_key": "k"},
        "ransomware_8k": {"enabled": True, "api_key": "k"},
        "ransomware_stats": {"enabled": True, "api_key": "k"},
        "red_flag_domains": {"enabled": True},
    })
    types = {type(s) for s in srcs}
    assert {RSS, RansomwareLive, RansomwarePress, Ransomware8K,
            RansomwareStats, RedFlagDomains} <= types


def test_build_sources_skips_disabled():
    assert _build({
        "rss": {"enabled": False, "feeds": []},
        "ransomware_live": {"enabled": False},
        "ransomware_press": {"enabled": False, "api_key": "k"},
    }) == []


def test_build_sources_passes_api_key_and_chain():
    srcs = _build({"ransomware_live": {"enabled": True, "api_key": "secret"}})
    rl = [s for s in srcs if isinstance(s, RansomwareLive)][0]
    assert rl.api_key == "secret"
    assert [n for n, _ in rl._chain()] == ["pro", "v2", "posts"]
