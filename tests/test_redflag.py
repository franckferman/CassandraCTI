import asyncio

from cassandra_cti.sources.redflag import RedFlagDomains

INDEX = """<html><body>
<a href="2026-07-04.txt">x</a>
<a href="2026-07-05.txt">y</a>
<a href="http://169.254.169.254/2026-07-06.txt">ssrf</a>
<a href="notadate.txt">z</a>
</body></html>"""


def test_pick_recent_rejects_absolute_ssrf_and_nondate_hrefs():
    # Every file in the index predates the lookback, so this exercises the
    # fallback: the newest *relative* date file, never the absolute 169.254 href.
    urls = RedFlagDomains()._pick_recent(INDEX)
    assert urls == ["https://dl.red.flag.domains/daily/2026-07-05.txt"]


def test_pick_recent_returns_every_missed_day_oldest_first():
    """Taking only the newest file loses one list per day of downtime, with
    nothing to notice it by: the next pass finds a newer file and the gap stays."""
    from datetime import datetime, timedelta, timezone
    days = [(datetime.now(timezone.utc) - timedelta(days=n)).strftime("%Y-%m-%d") for n in (4, 2, 1, 0)]
    index = "<html><body>" + "".join(f'<a href="{j}.txt">{j}</a>' for j in days) + "</body></html>"
    urls = RedFlagDomains(lookback_days=3)._pick_recent(index)
    assert [u.rsplit("/", 1)[-1] for u in urls] == [f"{j}.txt" for j in days[1:]]


def test_a_file_already_seen_is_not_downloaded_again(monkeypatch):
    from datetime import datetime, timezone
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    index = f'<html><a href="{day}.txt">x</a></html>'
    src = RedFlagDomains()
    calls = []

    async def fake_dl(url):
        calls.append(url)
        return b"evil.com\n" if url.endswith(".txt") else index.encode()

    monkeypatch.setattr(src, "_download", fake_dl)
    assert len(asyncio.run(src.fetch())) == 1
    assert len(asyncio.run(src.fetch())) == 0          # second pass: nothing new
    assert sum(1 for u in calls if u.endswith(".txt")) == 1


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
    assert ev.raw["date"] == "2026-07-05"      # via the fallback, the index is old
    assert ev.tags == ["domains"]
