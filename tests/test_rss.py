import asyncio

import feedparser

from cassandra_cti.sources.rss import RSS, clean_html

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
