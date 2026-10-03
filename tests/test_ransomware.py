from cassandra_cti.sources.ransomware_live import RansomwareLive, _parse_dt

PRO_REC = {
    "id": "x", "victim": "Acme", "group": "qilin", "country": "US",
    "activity": "Tech", "website": "acme.com",
    "discovered": "2026-07-06T14:56:41.7+00:00",
    "attackdate": "2026-07-06T14:38:45+00:00", "description": "desc",
    "infostealer": "", "data_size": None, "press": None,
    "post_url": "http://leak.onion", "permalink": "https://www.ransomware.live/id/x",
}
V2_REC = {
    "victim": "Acme", "group": "qilin", "country": "US", "activity": "Tech",
    "domain": "acme.com", "discovered": "2026-07-06T14:56:41+00:00",
    "description": "desc", "claim_url": "http://leak.onion",
    "url": "https://www.ransomware.live/id/x", "infostealer": "", "data_size": None,
}
POSTS_REC = {
    "post_title": "*.Acme", "group_name": "qilin", "country": "US",
    "activity": "Tech", "website": "acme.com",
    "discovered": "2026-07-06 14:56:41.7", "post_url": "http://leak.onion",
    "description": "desc",
}


def test_normalize_pro_record():
    ev = RansomwareLive(lookback_days=0)._normalize(PRO_REC, "pro")
    assert ev.title == "Acme by qilin"
    assert ev.raw["group_name"] == "qilin"
    assert ev.raw["website"] == "acme.com"
    assert ev.url == "https://www.ransomware.live/id/x"   # stable permalink preferred
    assert ev.raw["leak_url"] == "http://leak.onion"      # leak kept in raw
    assert ev.raw["backend"] == "pro"


def test_normalize_v2_maps_domain_and_claim_url():
    ev = RansomwareLive(lookback_days=0)._normalize(V2_REC, "v2")
    assert ev.raw["website"] == "acme.com"       # v2 'domain' -> website
    assert ev.url == "https://www.ransomware.live/id/x"   # v2 'url' (permalink) preferred
    assert ev.raw["leak_url"] == "http://leak.onion"      # v2 'claim_url' kept in raw


def test_normalize_posts_maps_legacy_fields_and_strips_wildcard():
    ev = RansomwareLive(lookback_days=0)._normalize(POSTS_REC, "posts")
    assert ev.title == "Acme by qilin"
    assert ev.raw["group_name"] == "qilin"


def test_lookback_filters_old_records():
    old = dict(PRO_REC, discovered="2000-01-01T00:00:00+00:00", attackdate="")
    assert RansomwareLive(lookback_days=1)._normalize(old, "pro") is None


def test_fallback_chain_depends_on_api_key():
    assert [n for n, _ in RansomwareLive(api_key="k")._chain()] == ["pro", "v2", "posts"]
    assert [n for n, _ in RansomwareLive()._chain()] == ["v2", "posts"]


def test_parse_dt_handles_iso_space_and_empty():
    assert _parse_dt("2026-07-06T14:56:41.77+00:00") is not None
    assert _parse_dt("2026-07-06 14:56:41.77") is not None
    assert _parse_dt("") is None
