"""emoji_for resolution order and rss title heuristics.

Order: custom_map > DEFAULT_MAP > rss title heuristic > per-source fallbacks
> generic "megaphone".
"""
from cassandra_cti.emoji import emoji_for, DEFAULT_MAP
from cassandra_cti.models import Event


def _ev(source, title="", url=None):
    return Event(source=source, title=title, url=url)


def test_custom_map_wins_over_default_map():
    # "ransomware.live" is in DEFAULT_MAP, but a custom mapping overrides it.
    ev = _ev("ransomware.live", title="x", url="https://acme.fr/")
    assert emoji_for(ev, {"ransomware.live": "CUSTOM"}) == "CUSTOM"


def test_default_map_wins_over_rss_title_heuristic():
    # Source is in DEFAULT_MAP -> its value wins even though the title would
    # otherwise trigger the "microsoft" rss heuristic.
    ev = _ev("rss:Krebs on Security", title="Microsoft patches a bug")
    assert emoji_for(ev) == DEFAULT_MAP["rss:Krebs on Security"]
    assert emoji_for(ev) != DEFAULT_MAP["rss:Microsoft Security"]


def test_custom_map_wins_over_rss_title_heuristic():
    ev = _ev("rss:Random Blog", title="cisco advisory")
    assert emoji_for(ev, {"rss:Random Blog": "CUSTOM"}) == "CUSTOM"


def test_rss_title_microsoft():
    ev = _ev("rss:Random Blog", title="Microsoft Outlook flaw")
    assert emoji_for(ev) == DEFAULT_MAP["rss:Microsoft Security"]


def test_rss_title_cisco():
    ev = _ev("rss:Random Blog", title="Cisco ASA vulnerability")
    assert emoji_for(ev) == "📡"


def test_rss_title_checkpoint():
    ev = _ev("rss:Random Blog", title="CheckPoint research finding")
    assert emoji_for(ev) == DEFAULT_MAP["rss:Checkpoint Research"]


def test_rss_title_unmatched_falls_back_to_newspaper():
    ev = _ev("rss:Random Blog", title="Some unrelated headline")
    assert emoji_for(ev) == DEFAULT_MAP["rss:Graham Cluley"]  # "📰"


def test_unknown_source_returns_megaphone():
    ev = _ev("totally.unknown.source", title="whatever")
    assert emoji_for(ev) == "📢"
