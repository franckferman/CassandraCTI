"""Offline parsing tests for the two newest sources (CISA KEV + abuse.ch feeds).
These were under-covered: registration was tested but not that raw feed payloads
turn into the right events. Feed I/O is stubbed (no network)."""
import asyncio
import json
from datetime import datetime, timedelta, timezone

from cassandra_cti.sources.cisa_kev import CisaKev
from cassandra_cti.sources.abusech import AbuseCh


def _days_ago(n):
    return (datetime.now(timezone.utc) - timedelta(days=n)).strftime("%Y-%m-%d")


# --------------------------------------------------------------------------- #
# CISA KEV
# --------------------------------------------------------------------------- #
def _kev_json():
    return json.dumps({"vulnerabilities": [
        {"cveID": "CVE-2026-1", "vendorProject": "Acme", "product": "VPN",
         "vulnerabilityName": "RCE", "shortDescription": "Actively exploited RCE.",
         "dateAdded": _days_ago(3), "dueDate": _days_ago(-14),
         "requiredAction": "Apply the vendor patch.",
         "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2019-9", "vendorProject": "Old", "product": "X",
         "vulnerabilityName": "old", "shortDescription": "stale",
         "dateAdded": _days_ago(900), "knownRansomwareCampaignUse": "Unknown"},
    ]}).encode()


def _kev(**kw):
    src = CisaKev(**kw)

    async def fake_dl():
        return _kev_json()
    src._download = fake_dl
    return src


def test_cisa_kev_maps_fields_and_tags():
    evs = asyncio.run(_kev(lookback_days=0).fetch())
    e = {x.raw["cve"]: x for x in evs}["CVE-2026-1"]
    assert e.source == "cisa.kev"
    assert e.raw["vendor"] == "Acme" and e.raw["product"] == "VPN"
    assert e.raw["ransomware_use"] is True
    assert "vulnerability" in e.tags and "kev" in e.tags and "ransomware" in e.tags
    assert e.url == "https://nvd.nist.gov/vuln/detail/CVE-2026-1"


def test_cisa_kev_lookback_drops_old_cves():
    cves = {x.raw["cve"] for x in asyncio.run(_kev(lookback_days=365).fetch())}
    assert "CVE-2026-1" in cves          # recent, kept
    assert "CVE-2019-9" not in cves      # 900 days old, dropped


def test_cisa_kev_max_items_caps():
    assert len(asyncio.run(_kev(lookback_days=0, max_items=1).fetch())) == 1


# --------------------------------------------------------------------------- #
# abuse.ch feeds
# --------------------------------------------------------------------------- #
def _abusech(payload, **kw):
    src = AbuseCh(**kw)

    async def fake_get(url, **kwargs):
        return payload
    src._get = fake_get
    return src


def test_abusech_feodo_parses_c2():
    payload = json.dumps([{"ip_address": "1.2.3.4", "port": 443, "malware": "Emotet",
                           "country": "US", "status": "online",
                           "last_online": "2026-08-01 10:00:00",
                           "as_number": 64500, "as_name": "X"}]).encode()
    evs = asyncio.run(_abusech(payload, api_key=None, feeds=["feodo"])._feodo())
    assert len(evs) == 1
    e = evs[0]
    assert e.source == "abuse.ch" and "ioc" in e.tags
    assert e.raw["ioc"] == "1.2.3.4:443" and e.raw["malware"] == "Emotet" and e.raw["feed"] == "feodo"


def test_abusech_urlhaus_parses_csv():
    csv = (b'# header comment\n'
           b'"1","2026-08-01 10:00:00","http://evil.test/x","online","2026-08-02",'
           b'"malware_download","emotet,exe","https://urlhaus.abuse.ch/url/1/"\n')
    evs = asyncio.run(_abusech(csv, api_key=None, feeds=["urlhaus"])._urlhaus())
    assert len(evs) == 1
    e = evs[0]
    assert e.raw["ioc"] == "http://evil.test/x" and e.raw["feed"] == "urlhaus"
    assert e.url == "https://urlhaus.abuse.ch/url/1/"


def test_abusech_threatfox_unique_url_per_ioc():
    payload = json.dumps({"data": [{"id": 123, "ioc": "5.6.7.8:80", "ioc_type": "ip:port",
                                    "malware_printable": "Qakbot", "confidence_level": 90,
                                    "first_seen": "2026-08-01 10:00:00",
                                    "threat_type": "botnet_cc", "reference": ""}]}).encode()
    evs = asyncio.run(_abusech(payload, api_key="K", feeds=["threatfox"])._threatfox())
    assert len(evs) == 1
    e = evs[0]
    assert e.raw["ioc"] == "5.6.7.8:80" and e.raw["malware"] == "Qakbot" and e.raw["feed"] == "threatfox"
    assert e.url == "https://threatfox.abuse.ch/ioc/123/"


def test_abusech_threatfox_noop_without_key():
    assert asyncio.run(AbuseCh(api_key=None, feeds=["threatfox"])._threatfox()) == []


def test_abusech_malwarebazaar_parses_hash():
    h = "a" * 64
    payload = json.dumps({"data": [{"sha256_hash": h, "signature": "Emotet",
                                    "file_type": "exe", "file_name": "x.exe",
                                    "first_seen": "2026-08-01 10:00:00"}]}).encode()
    evs = asyncio.run(_abusech(payload, api_key="K", feeds=["malwarebazaar"])._malwarebazaar())
    assert len(evs) == 1
    e = evs[0]
    assert e.raw["ioc"] == h and e.raw["ioc_type"] == "sha256" and e.raw["feed"] == "malwarebazaar"
    assert e.url == "https://bazaar.abuse.ch/sample/" + h + "/"


def test_abusech_fetch_interleaves_feeds():
    # feodo (public) + threatfox (keyed) both return one item -> round-robin gives both
    feodo = [{"ip_address": "1.1.1.1", "port": 1, "malware": "M", "status": "online",
              "last_online": "2026-08-01 10:00:00"}]
    tfox = {"data": [{"id": 9, "ioc": "2.2.2.2", "ioc_type": "ip", "malware_printable": "N",
                      "first_seen": "2026-08-01 10:00:00"}]}

    src = AbuseCh(api_key="K", feeds=["feodo", "threatfox"])

    async def fake_get(url, **kw):
        return json.dumps(tfox).encode() if "threatfox" in url else json.dumps(feodo).encode()
    src._get = fake_get
    feeds = {e.raw["feed"] for e in asyncio.run(src.fetch())}
    assert feeds == {"feodo", "threatfox"}
