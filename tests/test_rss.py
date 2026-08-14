import asyncio

import feedparser

from cassandra_cti.sources.rss import RSS, clean_html, tidy_summary


def test_tidy_summary_drops_dangling_excerpt():
    # feeds cut the description mid-sentence -> drop the trailing fragment
    s = ('Full first sentence about the bug.\n\n'
         'A complete second paragraph that ends properly here.\n\n'
         '"The authentication')
    out = tidy_summary(s)
    assert '"The authentication' not in out
    assert out.endswith('ends properly here. […]')


def test_tidy_summary_keeps_complete_text_untouched():
    # a complete single paragraph (even without a final period) must survive
    s = "Victim by group. Stolen: 300 GB 63,434 Files"
    assert tidy_summary(s) == s


def test_tidy_summary_caps_length_at_word_boundary():
    s = "word " * 500          # very long, single paragraph
    out = tidy_summary(s, max_len=100)
    assert len(out) <= 110 and out.endswith('[…]') and 'word' in out


def test_tidy_summary_empty():
    assert tidy_summary("") == "" and tidy_summary(None) == ""


RSS_XML = b"""<?xml version="1.0"?>
<rss version="2.0"><channel><title>c</title>
<item><title>Item 1</title><link>http://a/1</link>
<description>&lt;p&gt;body one&lt;/p&gt;</description>
<pubDate>Mon, 06 Jul 2026 14:00:00 GMT</pubDate></item>
</channel></rss>"""


def test_clean_html_strips_tags():
    assert clean_html("<p>Hello <b>world</b></p>") == "Hello world"
    assert clean_html("") == ""


def test_entry_to_event_maps_fields():
    entry = feedparser.parse(RSS_XML).entries[0]
    ev = RSS("X", "http://x", tags=["t"])._entry_to_event(entry)
    assert ev.title == "Item 1"
    assert ev.url == "http://a/1"
    assert ev.summary == "body one"           # HTML stripped
    assert ev.published_at is not None
    assert ev.source == "rss:X"
    assert ev.tags == ["t"]


def test_fetch_parses_valid_feed(monkeypatch):
    r = RSS("X", "http://x")

    async def fake_dl():
        return RSS_XML

    monkeypatch.setattr(r, "_download", fake_dl)
    evs = asyncio.run(r.fetch())
    assert len(evs) == 1
    assert evs[0].title == "Item 1"


def test_fetch_on_garbage_returns_empty(monkeypatch):
    r = RSS("X", "http://x")

    async def fake_dl():
        return b"this is not a feed <<< &&&"

    monkeypatch.setattr(r, "_download", fake_dl)
    assert asyncio.run(r.fetch()) == []
