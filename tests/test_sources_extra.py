import asyncio

from cassandra_cti.models import public_meta
from cassandra_cti.store import _kind
from cassandra_cti.sources import build_sources
from cassandra_cti.sources.cisa_kev import CisaKev, _parse_date
from cassandra_cti.sources.abusech import AbuseCh, _parse_dt


def test_kind_categories():
    assert _kind("ransomware.live") == "ransomware"
    assert _kind("red.flag.domains") == "redflag"
    assert _kind("cisa.kev") == "vuln"
    assert _kind("abuse.ch") == "ioc"
    assert _kind("rss:Krebs") == "rss"
    assert _kind("telegram:x") == "other"


def test_public_meta_whitelists_and_drops_empty():
    m = public_meta({"group_name": "qilin", "cve": "CVE-1", "empty": "", "secret": "x", "none": None})
    assert m == {"group_name": "qilin", "cve": "CVE-1"}
    assert public_meta(None) == {}


def test_kev_parse_date():
    assert _parse_date("2025-06-01").year == 2025
    assert _parse_date("nonsense") is None


def test_abusech_parse_dt():
    assert _parse_dt("2022-06-04 21:24:53").year == 2022
    assert _parse_dt("2026-03-07").month == 3
    assert _parse_dt("") is None


def test_abusech_threatfox_noop_without_key():
    # Offline: no api_key -> ThreatFox path returns [] with no network call.
    src = AbuseCh(api_key=None, feeds=["threatfox"])
    assert src.source == "abuse.ch"
    assert asyncio.run(src._threatfox()) == []


def test_build_sources_registers_new_sources():
    cfg = {"sources": {
        "cisa_kev": {"enabled": True},
        "abusech": {"enabled": True, "feeds": ["feodo"]},
    }}
    srcs = asyncio.run(build_sources(cfg))
    ids = {getattr(s, "source", None) for s in srcs}
    assert "cisa.kev" in ids
    assert "abuse.ch" in ids
    assert any(isinstance(s, CisaKev) for s in srcs)
    assert any(isinstance(s, AbuseCh) for s in srcs)


def test_build_sources_skips_when_disabled():
    srcs = asyncio.run(build_sources({"sources": {}}))
    ids = {getattr(s, "source", None) for s in srcs}
    assert "cisa.kev" not in ids and "abuse.ch" not in ids
