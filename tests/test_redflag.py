import asyncio

from cassandra_cti.sources.redflag import RedFlagDomains

INDEX = """<html><body>
<a href="2026-07-04.txt">x</a>
<a href="2026-07-05.txt">y</a>
<a href="http://169.254.169.254/2026-07-06.txt">ssrf</a>
<a href="notadate.txt">z</a>
</body></html>"""


def test_pick_latest_rejects_absolute_ssrf_and_nondate_hrefs():
    latest = RedFlagDomains()._pick_latest(INDEX)
    # the newest *relative* date file, never the absolute 169.254 href
    assert latest == "https://dl.red.flag.domains/daily/2026-07-05.txt"


def test_fetch_parses_domains_and_skips_indented_comments(monkeypatch):
    src = RedFlagDomains()

    async def fake_dl(url):
        if url.endswith(".txt"):
            return b"# comment\n  # indented comment\nevil1.com\n\nevil2.com\n"
        return INDEX.encode()

    monkeypatch.setattr(src, "_download", fake_dl)
    evs = asyncio.run(src.fetch())
    assert len(evs) == 1
    ev = evs[0]
    assert ev.raw["count"] == 2          # both comment lines skipped, blank skipped
    assert "evil1.com" in ev.summary and "evil2.com" in ev.summary
    assert ev.raw["date"] == "2026-07-05"
    assert ev.tags == ["domains"]
