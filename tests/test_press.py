import asyncio

from cassandra_cti.sources.ransomware_press import RansomwarePress

RESULTS = [
    {"date": "2026-07-05", "victim": "Pennington County",
     "domain": "pennington.sd.us", "country": "US",
     "summary": "cyber incident summary"},
]


def test_press_skips_gracefully_without_key():
    # PRO-only feed with no fallback: must return [] (not raise) when unkeyed.
    assert asyncio.run(RansomwarePress(api_key="").fetch()) == []


def test_press_placeholder_key_treated_as_missing():
    src = RansomwarePress(api_key="${RANSOMWARE_API_KEY}")
    assert src.api_key == ""
    assert asyncio.run(src.fetch()) == []


def test_press_normalize_maps_verified_fields():
    evs = RansomwarePress(api_key="k")._normalize(RESULTS)
    assert len(evs) == 1
    ev = evs[0]
    assert ev.title == "Pennington County"
    assert ev.url is None                      # /press/recent has no article URL
    assert ev.summary == "cyber incident summary"
    assert ev.tags == ["press", "news"]
    assert ev.published_at is not None
    assert ev.raw["country"] == "US"
