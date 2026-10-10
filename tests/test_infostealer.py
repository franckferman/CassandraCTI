from cassandra_cti.sources.ransomware_live import (
    _infostealer_summary, _infostealer_stealers,
)


def test_summary_lists_nonzero_counts():
    info = {"users": 15, "employees": 6, "thirdparties": 0}
    assert _infostealer_summary(info) == "15 users, 6 employees"


def test_summary_all_zero_is_empty():
    # ransomware.live attaches the object even when it correlated nothing.
    assert _infostealer_summary({"users": 0, "employees": 0, "thirdparties": 0}) == ""


def test_summary_thirdparties_only():
    assert _infostealer_summary({"users": 0, "employees": 0, "thirdparties": 3}) == "3 third-parties"


def test_summary_non_dict_is_empty():
    assert _infostealer_summary("") == ""
    assert _infostealer_summary(None) == ""
    assert _infostealer_summary(True) == ""


def test_stealers_ranked_top_n():
    info = {"infostealer_stats": {"Lumma": 137, "RedLine": 132, "Vidar": 36,
                                  "StealC": 14, "Raccoon": 43, "Zero": 0}}
    out = _infostealer_stealers(info, top=3)
    assert out == "Lumma (137), RedLine (132), Raccoon (43)"   # ranked desc, zeros dropped


def test_stealers_empty_stats():
    assert _infostealer_stealers({"infostealer_stats": {}}) == ""
    assert _infostealer_stealers({"users": 5}) == ""
    assert _infostealer_stealers("") == ""
