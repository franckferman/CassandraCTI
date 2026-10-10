import asyncio

from cassandra_cti.sources.ransomware_8k import Ransomware8K

FORMS = {"forms": [
    {"company": "Theravance Biopharma, Inc.", "stockticker": "TBPH", "form": "8-K",
     "file_date": "2026-06-29", "link": "https://sec.gov/tbph",
     "item105": False, "item801": True},
    {"company": "Acme", "stockticker": "ACM", "form": "8-K",
     "file_date": "2026-07-01", "link": "https://sec.gov/acme",
     "item105": True, "item801": False},
]}


def test_8k_skips_without_key():
    assert asyncio.run(Ransomware8K(api_key="").fetch()) == []


def test_8k_normalize_sorts_desc_and_maps_verified_fields():
    evs = Ransomware8K(api_key="k")._normalize(FORMS)
    assert len(evs) == 2
    assert evs[0].raw["file_date"] == "2026-07-01"     # most recent first
    assert evs[0].title == "Acme (ACM)"
    assert evs[0].url == "https://sec.gov/acme"         # real SEC link -> dedup key
    assert "Item 1.05" in evs[0].summary
    assert evs[0].tags == ["sec", "8k", "disclosure"]
    assert evs[0].published_at is not None
