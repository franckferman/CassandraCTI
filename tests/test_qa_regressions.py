"""Regression tests for the defects found while qualifying the Teams pipeline
against a live tenant. Each test names the behaviour that was wrong and pins the
behaviour that replaced it. Offline: no network, no webhook.
"""
import asyncio
import logging
import os
import re

import yaml
from jinja2 import Template

import cassandra_cti.main as main
from cassandra_cti.emoji import emoji_for
from cassandra_cti.models import Event
from cassandra_cti.sources.abusech import AbuseCh
from cassandra_cti.sources.redflag import RedFlagDomains
from cassandra_cti.sources.rss import RSS
from cassandra_cti.store import Store
from cassandra_cti.transports.teams import TeamsTransport

ROOT = os.path.join(os.path.dirname(__file__), os.pardir)
TEMPLATES = os.path.join(ROOT, "templates")


# --------------------------------------------------------------------------
# Harness (same shape as test_run_once.py, kept local so this file stands alone)
# --------------------------------------------------------------------------

class FakeSource:
    def __init__(self, source, events):
        self.source = source
        self._events = events

    async def fetch(self):
        return list(self._events)


class FakeTransport:
    def __init__(self, batch_cfg=None):
        self.batch_cfg = batch_cfg or {}
        self.sent = []

    async def send(self, chunk, title=None, template_text=None):
        self.sent.append({"chunk": list(chunk), "title": title})

    async def aclose(self):
        pass


def _cfg(tmp_path, routes, filters=None, store=None):
    data = {
        "schema_version": 1,
        "sources": {},
        "transports": {"teams": [{"id": "t1", "webhook_url": "http://x"}]},
        "routes": routes,
        "store": {"sqlite_path": "cti.db", **(store or {})},
        "metrics": {"enabled": False},
        "filters": filters or {},
    }
    cfg = tmp_path / "config.yaml"
    cfg.write_text(yaml.safe_dump(data))
    return str(cfg)


def _run(cfg, monkeypatch, sources, batch_cfg=None):
    built = []

    def fake_build_transport(ttype, params):
        tr = FakeTransport(batch_cfg=batch_cfg)
        built.append(tr)
        return tr

    async def fake_build_sources(_cfg):
        return [FakeSource(src, evs) for src, evs in sources]

    monkeypatch.setattr(main, "build_transport", fake_build_transport)
    monkeypatch.setattr(main, "build_sources", fake_build_sources)
    monkeypatch.delenv("CTI_DRY_RUN", raising=False)
    asyncio.run(main.run_once(cfg))
    return built


def _titles(tr):
    return [ev.title for call in tr.sent for ev in call["chunk"]]


def _dated(n, source="rss:X"):
    """n events, OLDEST first, as a chronological feed such as CERT-FR serves them."""
    from datetime import datetime, timezone
    return [Event(source=source, title=f"t{i}", url=f"https://e/{i}",
                  published_at=datetime(2026, 1, 1 + i, tzinfo=timezone.utc))
            for i in range(n)]


# --------------------------------------------------------------------------
# The per-source cap used to keep the OLDEST entries
# --------------------------------------------------------------------------

def test_cap_keeps_the_most_recent_entries(tmp_path, monkeypatch):
    # A chronological feed (oldest first) capped at 2 used to deliver its two
    # oldest entries; once marked delivered, the recent ones were never reached.
    cfg = _cfg(tmp_path, [{"name": "r", "include_sources": ["rss:X"], "transports": ["t1"]}],
               filters={"max_items_per_source": 2})
    tr = _run(cfg, monkeypatch, [("rss:X", _dated(5))])[0]
    assert _titles(tr) == ["t3", "t4"]


def test_delivery_order_is_chronological(tmp_path, monkeypatch):
    # The most recent item must arrive last in the channel, where a reader looks first.
    cfg = _cfg(tmp_path, [{"name": "r", "include_sources": ["rss:X"], "transports": ["t1"]}],
               filters={"max_items_per_source": 3})
    tr = _run(cfg, monkeypatch, [("rss:X", _dated(4))])[0]
    assert _titles(tr) == ["t1", "t2", "t3"]


def test_undated_entries_survive_the_cap(tmp_path, monkeypatch):
    # An entry without a date is treated as most recent, never starved by the cap.
    evs = _dated(3) + [Event(source="rss:X", title="nodate", url="https://e/nd")]
    cfg = _cfg(tmp_path, [{"name": "r", "include_sources": ["rss:X"], "transports": ["t1"]}],
               filters={"max_items_per_source": 1})
    tr = _run(cfg, monkeypatch, [("rss:X", evs)])[0]
    assert _titles(tr) == ["nodate"]


# --------------------------------------------------------------------------
# A feed title could inject HTML into the card
# --------------------------------------------------------------------------

PIEGE = 'Fix <a href="https://evil.example/pwn">CLICK NOW</a> available'


def _payload(tr, ev, template_text=None):
    box = {}

    async def fake_post(payload):
        box["payload"] = payload

    tr._post = fake_post
    asyncio.run(tr.send([ev], title="rss:Feed", template_text=template_text))
    return box["payload"]


def test_feed_title_cannot_inject_html_through_a_template():
    tr = TeamsTransport(webhook_url="https://teams.test/wh", throttle_ms=0, emojis=False)
    tpl = open(os.path.join(TEMPLATES, "rss_default.j2"), encoding="utf-8").read()
    text = _payload(tr, Event(source="rss:F", title=PIEGE, url="https://e/1", summary="s"), tpl)["text"]
    assert "&lt;a href=" in text
    assert '<a href="https://evil.example/pwn">' not in text


def test_feed_title_cannot_inject_html_without_a_template():
    tr = TeamsTransport(webhook_url="https://teams.test/wh", throttle_ms=0, emojis=False)
    ev = Event(source="rss:F", title="t", url="https://e/1", summary=PIEGE)
    text = _payload(tr, ev)["text"]
    assert '<a href="https://evil.example/pwn">' not in text


def test_escaping_keeps_the_source_link_usable():
    tr = TeamsTransport(webhook_url="https://teams.test/wh", throttle_ms=0, emojis=False)
    tpl = open(os.path.join(TEMPLATES, "rss_default.j2"), encoding="utf-8").read()
    ev = Event(source="rss:F", title="t", url="https://e/x?a=1&b=2", summary="s")
    text = _payload(tr, ev, tpl)["text"]
    assert "https://e/x?a=1&amp;b=2" in text  # HTML-encoded ampersand, decoded by the client


# --------------------------------------------------------------------------
# A truncated feed published an empty "(no title)" card
# --------------------------------------------------------------------------

def test_entry_without_title_and_link_is_skipped(monkeypatch, caplog):
    src = RSS(name="Broken", url="http://x/feed")

    async def fake_dl():
        return b"<?xml version='1.0'?><rss><channel><title>c</title><item><title>never closed"

    monkeypatch.setattr(src, "_download", fake_dl)
    with caplog.at_level(logging.WARNING):
        assert asyncio.run(src.fetch()) == []
    assert "without title and link" in caplog.text


def test_entry_with_a_title_but_no_link_is_kept(monkeypatch):
    src = RSS(name="NoLink", url="http://x/feed")

    async def fake_dl():
        return (b"<?xml version='1.0'?><rss version='2.0'><channel><title>c</title>"
                b"<item><title>Real advisory</title></item></channel></rss>")

    monkeypatch.setattr(src, "_download", fake_dl)
    out = asyncio.run(src.fetch())
    assert [e.title for e in out] == ["Real advisory"]


# --------------------------------------------------------------------------
# Templates
# --------------------------------------------------------------------------

def _render(name, **ctx):
    return Template(open(os.path.join(TEMPLATES, name), encoding="utf-8").read()).render(**ctx)


def test_rss_template_emits_no_dead_link_without_url():
    out = _render("rss_default.j2", title="t", source="s", summary="body", url="", raw={})
    assert "View Link" not in out


def test_domains_template_links_the_source_below_fifty():
    out = _render("domains_list.j2", title="Red Flag Domains", url="https://dl/x.txt",
                  summary="\n".join(f"d{i}.fr" for i in range(5)), raw={"count": 5})
    assert "full list" in out and "https://dl/x.txt" in out


def test_domains_template_truncates_above_fifty():
    out = _render("domains_list.j2", title="Red Flag Domains", url="https://dl/x.txt",
                  summary="\n".join(f"d{i}.fr" for i in range(120)), raw={"count": 120})
    assert "Extrait (50/120)" in out or "(50/120)" in out
    assert "70 more domains" in out


# --------------------------------------------------------------------------
# Batching was disabled by ANY route template
# --------------------------------------------------------------------------

def test_template_uses_events_detection():
    f = main._template_uses_events
    assert f("{% for e in events %}{{ e.title }}{% endfor %}") is True
    assert f("{{ events | length }}") is True
    assert f("**{{ title }}**\n[View Link]({{ url }})") is False
    # a substring match would be fooled by the word in a comment
    assert f("{# one event per card, not events #}{{ title }}") is False
    assert f("{{ unclosed") is False


def test_batching_applies_to_a_template_that_iterates_events(tmp_path, monkeypatch):
    routes = [{"name": "r", "include_sources": ["rss:X"], "transports": ["t1"],
               "template": "templates/batch_default.j2"}]
    cfg = _cfg(tmp_path, routes)
    tr = _run(cfg, monkeypatch, [("rss:X", _dated(7))],
              batch_cfg={"enabled": True, "max_items": 5})[0]
    assert [len(c["chunk"]) for c in tr.sent] == [5, 2]


def test_batching_stays_off_for_a_per_item_template(tmp_path, monkeypatch):
    routes = [{"name": "r", "include_sources": ["rss:X"], "transports": ["t1"],
               "template": "templates/rss_default.j2"}]
    cfg = _cfg(tmp_path, routes)
    tr = _run(cfg, monkeypatch, [("rss:X", _dated(4))],
              batch_cfg={"enabled": True, "max_items": 5})[0]
    assert [len(c["chunk"]) for c in tr.sent] == [1, 1, 1, 1]


# --------------------------------------------------------------------------
# An advisory revised upstream was never delivered again
# --------------------------------------------------------------------------

def test_upsert_event_reports_a_content_revision(tmp_path):
    s = Store(str(tmp_path / "s.db"))
    assert s.upsert_event("e1", "rss:A", "https://a/1", "Advisory", "body", None) is False
    assert s.upsert_event("e1", "rss:A", "https://a/1", "Advisory", "body", None) is False
    assert s.upsert_event("e1", "rss:A", "https://a/1", "[MaJ] Advisory", "body", None) is True
    assert s.upsert_event("e1", "rss:A", "https://a/1", "[MaJ] Advisory", "new body", None) is True


def test_resend_on_update_redelivers_only_the_revision(tmp_path, monkeypatch):
    routes = [{"name": "r", "include_sources": ["rss:X"], "transports": ["t1"]}]
    ev = Event(source="rss:X", title="Advisory", url="https://e/1", summary="body")
    revise = Event(source="rss:X", title="[MaJ] Advisory", url="https://e/1", summary="fixed")

    cfg = _cfg(tmp_path, routes, store={"resend_on_update": True})
    assert len(_run(cfg, monkeypatch, [("rss:X", [ev])])[0].sent) == 1
    assert len(_run(cfg, monkeypatch, [("rss:X", [ev])])[0].sent) == 0      # unchanged
    assert len(_run(cfg, monkeypatch, [("rss:X", [revise])])[0].sent) == 1  # revised
    assert len(_run(cfg, monkeypatch, [("rss:X", [revise])])[0].sent) == 0  # no loop


def test_resend_on_update_is_off_by_default(tmp_path, monkeypatch):
    routes = [{"name": "r", "include_sources": ["rss:X"], "transports": ["t1"]}]
    ev = Event(source="rss:X", title="Advisory", url="https://e/1", summary="body")
    revise = Event(source="rss:X", title="[MaJ] Advisory", url="https://e/1", summary="fixed")
    cfg = _cfg(tmp_path, routes)
    assert len(_run(cfg, monkeypatch, [("rss:X", [ev])])[0].sent) == 1
    assert len(_run(cfg, monkeypatch, [("rss:X", [revise])])[0].sent) == 0


# --------------------------------------------------------------------------
# The emoji described the article while the card title named the source
# --------------------------------------------------------------------------

def test_emoji_follows_the_source_when_the_title_is_imposed():
    ev = Event(source="rss:CERT-FR Alertes", title="Vulnerabilities in Microsoft Sharepoint")
    assert emoji_for(ev) == "Ⓜ️"                        # legacy: keyed on the article
    assert emoji_for(ev, by_source_only=True) == "📰"    # card titled with the source


def test_custom_map_still_wins_over_source_only():
    ev = Event(source="rss:CERT-FR Alertes", title="Microsoft")
    assert emoji_for(ev, {"rss:CERT-FR Alertes": "🇫🇷"}, by_source_only=True) == "🇫🇷"


def test_teams_card_title_emoji_ignores_the_article(monkeypatch):
    tr = TeamsTransport(webhook_url="https://teams.test/wh", throttle_ms=0, emojis=True)
    ev = Event(source="rss:CERT-FR Alertes", title="Flaw in Microsoft Sharepoint", url="https://e/1")
    assert _payload(tr, ev)["title"].startswith("📰")


# --------------------------------------------------------------------------
# Sources that failed or were key-gated said nothing
# --------------------------------------------------------------------------

def test_redflag_logs_an_unreachable_index(monkeypatch, caplog):
    src = RedFlagDomains(base_url="http://dl.test/daily/")

    async def boom(url):
        raise RuntimeError("HTTP 404 fetching " + url)

    monkeypatch.setattr(src, "_download", boom)
    with caplog.at_level(logging.WARNING):
        assert asyncio.run(src.fetch()) == []
    assert "index" in caplog.text and "unreachable" in caplog.text


def test_redflag_logs_an_index_without_any_dated_file(monkeypatch, caplog):
    src = RedFlagDomains(base_url="http://dl.test/daily/")

    async def index(url):
        return b"<html><body><a href='readme.txt'>x</a></body></html>"

    monkeypatch.setattr(src, "_download", index)
    with caplog.at_level(logging.WARNING):
        assert asyncio.run(src.fetch()) == []
    assert "no YYYY-MM-DD.txt" in caplog.text


def test_abusech_says_when_a_feed_needs_a_key(caplog):
    src = AbuseCh(api_key=None, feeds=["threatfox"])
    with caplog.at_level(logging.WARNING):
        assert asyncio.run(src._threatfox()) == []
    assert "threatfox" in caplog.text and "Auth-Key" in caplog.text


# --------------------------------------------------------------------------
# The shipped example promised a throughput the transport refuses
# --------------------------------------------------------------------------

def test_example_teams_connectors_respect_the_throttle_floor():
    raw = open(os.path.join(ROOT, "connectors.example.yaml"), encoding="utf-8").read()
    data = yaml.safe_load(re.sub(r"\$\{[^}]+\}", "placeholder", raw))
    for c in data["connectors"]:
        if c.get("type") == "teams":
            throttle = c.get("params", {}).get("throttle_ms", 1000)
            assert throttle >= 1000, f"{c['id']}: throttle_ms={throttle} is raised to 1000 anyway"


# --------------------------------------------------------------------------
# The fetcher claimed to be Chrome, which several sites answered with a 403
# --------------------------------------------------------------------------

def test_default_user_agent_identifies_the_tool():
    from cassandra_cti.sources.rss import resolve_user_agent
    ua = resolve_user_agent(None)
    assert "CassandraCTI" in ua
    assert "Chrome" not in ua and "Mozilla" not in ua


def test_user_agent_presets_and_verbatim_values():
    from cassandra_cti.sources.rss import resolve_user_agent
    assert "Firefox" in resolve_user_agent("firefox")
    assert "Firefox" in resolve_user_agent("FIREFOX")      # preset names are case-insensitive
    assert "Chrome" in resolve_user_agent("chrome")        # still available when a site wants it
    assert resolve_user_agent("MyReader/1.0") == "MyReader/1.0"


def test_user_agent_per_source_default_and_per_feed_override():
    from cassandra_cti.sources.rss import build_rss_sources
    srcs = build_rss_sources({
        "user_agent": "feedreader",
        "feeds": [
            {"name": "A", "url": "http://a/", "tags": []},
            {"name": "B", "url": "http://b/", "tags": [], "user_agent": "firefox"},
        ],
    })
    assert "Feedly" in srcs[0].user_agent
    assert "Firefox" in srcs[1].user_agent


def test_the_configured_user_agent_is_the_one_sent(monkeypatch):
    import asyncio
    from cassandra_cti.sources.rss import RSS
    src = RSS(name="X", url="http://x/feed", user_agent="MyReader/1.0")
    assert src.user_agent == "MyReader/1.0"

    vu = {}

    async def fake_dl():
        vu["ua"] = src.user_agent
        return (b"<?xml version='1.0'?><rss version='2.0'><channel><title>c</title>"
                b"<item><title>t</title><link>http://x/1</link></item></channel></rss>")

    monkeypatch.setattr(src, "_download", fake_dl)
    asyncio.run(src.fetch())
    assert vu["ua"] == "MyReader/1.0"


# --------------------------------------------------------------------------
# A briefing with no template rendered with the per-alert layout
# --------------------------------------------------------------------------

def test_briefing_without_a_template_renders_the_body_not_the_alert_layout():
    from cassandra_cti.briefings import _DEFAULT_TEMPLATE, _load_template
    tpl = _load_template(None) or _DEFAULT_TEMPLATE
    out = Template(tpl).render(summary="Top 5: ...", source="news-24h", title="Point News")
    assert out.strip().startswith("Top 5: ...")
    assert "Source:" not in out      # the card title already names the briefing
    assert "news-24h" not in out     # the internal name has no business on the card


def test_a_configured_briefing_template_still_wins(tmp_path):
    from cassandra_cti.briefings import _DEFAULT_TEMPLATE, _load_template
    p = tmp_path / "custom.j2"
    p.write_text("CUSTOM {{ summary }}", encoding="utf-8")
    tpl = _load_template(str(p)) or _DEFAULT_TEMPLATE
    assert Template(tpl).render(summary="x") == "CUSTOM x"


# --------------------------------------------------------------------------
# The same ransomware victim was delivered twice when the backend fell back
# --------------------------------------------------------------------------

def test_dedup_key_survives_a_missing_url():
    from cassandra_cti.util import make_event_id
    title = "Poca Valley Bank by Storm"
    with_url = make_event_id("ransomware.live", "https://www.ransomware.live/id/UG9jYQ==", title, dedup_key="Poca Valley Bank@Storm")
    without_url = make_event_id("ransomware.live", None, title, dedup_key="Poca Valley Bank@Storm")
    onion = make_event_id("ransomware.live", "http://yqhecvq.onion/", title, dedup_key="Poca Valley Bank@Storm")
    assert with_url == without_url == onion


def test_without_a_dedup_key_the_url_still_drives_identity():
    from cassandra_cti.util import make_event_id
    a = make_event_id("rss:X", "https://e/1", "t")
    b = make_event_id("rss:X", "https://e/2", "t")
    assert a != b


def test_ransomware_event_never_labels_an_onion_as_its_source():
    from cassandra_cti.sources.ransomware_live import RansomwareLive
    src = RansomwareLive(lookback_days=0)
    # posts.json shape: no permalink, only a leak site
    ev = src._normalize({"post_title": "ACME", "group_name": "storm",
                         "post_url": "http://abcdef.onion/acme",
                         "discovered": "2026-09-30T03:00:00+00:00"}, "posts")
    assert ev is not None
    assert ev.url is None                       # the card would have said "Source (ransomware.live)"
    assert ev.raw["leak_url"] == "http://abcdef.onion/acme"   # still available to the template
    assert ev.dedup_key == "ACME@storm"


def test_ransomware_event_keeps_the_page_url_when_the_backend_provides_one():
    from cassandra_cti.sources.ransomware_live import RansomwareLive
    src = RansomwareLive(lookback_days=0)
    ev = src._normalize({"victim": "ACME", "group": "storm",
                         "url": "https://www.ransomware.live/id/QUNNRQ==",
                         "post_url": "http://abcdef.onion/acme",
                         "discovered": "2026-09-30T03:00:00+00:00"}, "v2")
    assert ev.url == "https://www.ransomware.live/id/QUNNRQ=="
    assert ev.dedup_key == "ACME@storm"


# --------------------------------------------------------------------------
# Credit belongs on what the tool authors, not on what it relays
# --------------------------------------------------------------------------

def test_the_briefing_is_credited():
    from cassandra_cti.briefings import _DEFAULT_TEMPLATE
    out = Template(_DEFAULT_TEMPLATE).render(summary="Top 5: ...")
    assert "CassandraCTI" in out
    tpl = open(os.path.join(TEMPLATES, "briefing_default.j2"), encoding="utf-8").read()
    assert "CassandraCTI" in Template(tpl).render(summary="Top 5: ...")


def test_relayed_alerts_carry_no_credit():
    # An alert card relays a CERT-FR or vendor advisory: the tool transports it,
    # it does not author it, so it signs nothing.
    for name in ("rss_default.j2", "ransomware_card.j2", "domains_list.j2", "vuln_card.j2"):
        tpl = open(os.path.join(TEMPLATES, name), encoding="utf-8").read()
        assert "CassandraCTI" not in tpl, f"{name} signs content it did not write"


# --------------------------------------------------------------------------
# A 202 from Workflows means "accepted", never "posted"
# --------------------------------------------------------------------------

class _FausseReponse:
    def __init__(self, headers, status=200):
        self.status = status
        self.headers = headers

    async def text(self):
        return ""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _FausseSession:
    def __init__(self, reponse):
        self._r = reponse
        self.closed = False

    def post(self, *a, **k):
        return self._r


def _poste(tr, headers, caplog_level=logging.DEBUG):
    tr._session = _FausseSession(_FausseReponse(headers))

    async def rien():
        pass

    tr._ensure_session = rien
    asyncio.run(tr._post({"@type": "MessageCard"}))


def test_the_power_automate_run_id_is_logged(caplog):
    tr = TeamsTransport(webhook_url="https://teams.test/wh", throttle_ms=0)
    with caplog.at_level(logging.DEBUG, logger="cassandra-cti.teams"):
        _poste(tr, {"x-ms-workflow-run-id": "0858410659694341236"})
    assert "0858410659694341236" in caplog.text


def test_a_low_burst_quota_is_reported(caplog):
    tr = TeamsTransport(webhook_url="https://teams.test/wh", throttle_ms=0, quota_warn=50)
    with caplog.at_level(logging.WARNING, logger="cassandra-cti.teams"):
        _poste(tr, {"x-ms-ratelimit-burst-remaining-workflow-writes": "12",
                    "x-ms-workflow-run-id": "run-1"})
    assert "12 writes left" in caplog.text


def test_a_healthy_quota_stays_quiet(caplog):
    tr = TeamsTransport(webhook_url="https://teams.test/wh", throttle_ms=0, quota_warn=50)
    with caplog.at_level(logging.WARNING, logger="cassandra-cti.teams"):
        _poste(tr, {"x-ms-ratelimit-burst-remaining-workflow-writes": "561"})
    assert "writes left" not in caplog.text


def test_an_event_with_a_dedup_key_is_not_resent_on_the_next_run(tmp_path, monkeypatch):
    """The round trip, not the hash in isolation.

    The dedup check and the delivery record must agree on the identity. They
    diverged once: the check used the dedup_key, the record recomputed the id
    from the URL, and ransomware victims were re-sent at every single pass.
    """
    from datetime import datetime, timezone
    ev = Event(source="ransomware.live", title="ACME by storm", url=None,
               published_at=datetime(2026, 9, 30, tzinfo=timezone.utc),
               dedup_key="ACME@storm")
    routes = [{"name": "r", "include_sources": ["ransomware.live"], "transports": ["t1"]}]
    cfg = _cfg(tmp_path, routes)

    assert len(_run(cfg, monkeypatch, [("ransomware.live", [ev])])[0].sent) == 1
    assert len(_run(cfg, monkeypatch, [("ransomware.live", [ev])])[0].sent) == 0
    assert len(_run(cfg, monkeypatch, [("ransomware.live", [ev])])[0].sent) == 0


def test_an_event_without_a_dedup_key_is_not_resent_either(tmp_path, monkeypatch):
    ev = Event(source="rss:X", title="t", url="https://e/1")
    routes = [{"name": "r", "include_sources": ["rss:X"], "transports": ["t1"]}]
    cfg = _cfg(tmp_path, routes)
    assert len(_run(cfg, monkeypatch, [("rss:X", [ev])])[0].sent) == 1
    assert len(_run(cfg, monkeypatch, [("rss:X", [ev])])[0].sent) == 0


def test_the_card_heading_and_its_body_agree_on_the_emoji():
    """Two call sites computed the emoji differently on the same card: the
    heading from the source, the template variable from the article title."""
    tr = TeamsTransport(webhook_url="https://teams.test/wh", throttle_ms=0, emojis=True)
    ev = Event(source="rss:CERT-FR Alertes", title="Flaw in Microsoft Sharepoint", url="https://e/1")
    p = _payload(tr, ev, template_text="{{ emoji }}|{{ title }}")
    heading = p["title"].split(" ")[0]
    body = p["text"].split("|")[0]
    assert heading == body == "📰"


def test_a_capped_briefing_tells_the_model_what_it_is_not_seeing(monkeypatch):
    """The card heading counts every selected event, the model only sees
    max_items of them. Unless told, it writes "all 40 items" under a heading
    that says 88."""
    import asyncio
    from cassandra_cti.briefings import _make_brief
    from types import SimpleNamespace
    seen = {}

    class _LLM:
        async def complete(self, prompt, system=None):
            seen["prompt"] = prompt
            return "ok"

    b = SimpleNamespace(name="rw", max_items=3, top_n=5)
    evs = [{"source": "ransomware.live", "title": f"v{i}", "url": f"https://e/{i}"} for i in range(9)]
    asyncio.run(_make_brief(_LLM(), b, evs, "24h"))
    assert "3 most recent of 9 collected" in seen["prompt"]

    asyncio.run(_make_brief(_LLM(), b, evs[:2], "24h"))
    assert "Items (2)" in seen["prompt"]        # no cap, no noise


def test_sources_are_fetched_under_a_concurrency_bound(tmp_path, monkeypatch):
    """Over forty simultaneous lookups against a resolver that blinks returns
    EAI_AGAIN, and each loss looks like an unrelated site outage."""
    in_flight, peak = [], {"n": 0}

    class _Slow:
        def __init__(self, i):
            self.source = f"rss:s{i}"

        async def fetch(self):
            in_flight.append(self.source)
            peak["n"] = max(peak["n"], len(in_flight))
            await asyncio.sleep(0.02)
            in_flight.pop()
            return []

    srcs = [_Slow(i) for i in range(20)]

    async def fake_build_sources(_cfg):
        return srcs

    monkeypatch.setattr(main, "build_sources", fake_build_sources)
    monkeypatch.setattr(main, "build_transport", lambda t, p: FakeTransport())
    monkeypatch.delenv("CTI_DRY_RUN", raising=False)

    path = _cfg(tmp_path, [{"name": "r", "transports": ["t1"]}])
    data = yaml.safe_load(open(path))
    data["scheduler"] = {"max_concurrent_fetches": 4}
    open(path, "w").write(yaml.safe_dump(data))
    asyncio.run(main.run_once(path))
    assert peak["n"] <= 4, f"{peak['n']} fetches at once despite a bound of 4"
    assert peak["n"] > 1, "the bound must not serialise everything"


def test_cves_are_listed_in_the_order_an_advisory_lists_them():
    from cassandra_cti.util import extract_cves
    assert extract_cves("CVE-2026-11224 and CVE-2026-11223") == ["CVE-2026-11223", "CVE-2026-11224"]
    assert extract_cves("cve-2025-9999 then CVE-2026-1000") == ["CVE-2025-9999", "CVE-2026-1000"]
    assert extract_cves("CVE-2026-1234 twice CVE-2026-1234") == ["CVE-2026-1234"]
    assert extract_cves(None, "", "no identifier here") == []
    assert extract_cves("CVE-20-1 is not one") == []       # four digits minimum


def test_the_rss_card_drops_the_source_line_and_caps_the_excerpt():
    """The heading is the source name, so the body must keep the article title.
    What it must not keep is a "Source:" line repeating that heading, or the
    full 1500-character summary the fetcher allows."""
    from datetime import datetime, timezone
    from cassandra_cti.util import template_context
    from jinja2 import Template
    tpl = Template(open("templates/rss_default.j2").read(), autoescape=True)
    ev = Event(source="rss:CERT-FR Avis", title="A very distinctive headline",
               url="https://e/1", summary="CVE-2026-11223 then " + "x" * 900,
               published_at=datetime(2026, 10, 1, tzinfo=timezone.utc))
    out = tpl.render(**template_context(ev, [ev], "📰"))
    assert "A very distinctive headline" in out      # the heading says only the feed
    assert "Source:" not in out
    assert "CVE-2026-11223" in out and "2026-10-01" in out
    assert "[…]" in out and len(out) < 600           # excerpt, not the whole 900
    assert "[Read the full item](https://e/1)" in out


# --------------------------------------------------------------------------
# ransomware.live: every backend lives on one project's infrastructure
# --------------------------------------------------------------------------

def test_a_successful_fetch_writes_the_mirror_and_an_outage_serves_it(tmp_path, monkeypatch):
    """If the project goes away, the chain ends at a remote URL and the source
    errors on every pass. The mirror is the last link, and it is maintained by
    normal operation so there is no second service to forget to start."""
    import json
    from cassandra_cti.sources.ransomware_live import RansomwareLive

    path = tmp_path / "mirror.json"
    victims = [{"victim": "ACME", "group_name": "storm", "discovered": "2026-10-01 10:00:00.000000", "post_url": "https://x/1"}]
    src = RansomwareLive(lookback_days=3650, mirror_path=str(path))

    async def ok(url, headers=None):
        return {"victims": victims}

    monkeypatch.setattr(src, "_get_json", ok)
    assert len(asyncio.run(src.fetch())) == 1
    written = json.loads(path.read_text())
    assert written["backend"] == "v2" and len(written["records"]) == 1
    assert written["fetched_at"]

    # every remote backend now refuses
    outage = RansomwareLive(lookback_days=3650, mirror_path=str(path))

    async def dead(url, headers=None):
        raise RuntimeError("host unreachable")

    monkeypatch.setattr(outage, "_get_json", dead)
    evs = asyncio.run(outage.fetch())
    assert len(evs) == 1 and evs[0].title.startswith("ACME")


def test_no_mirror_path_means_no_mirror_and_no_crash(tmp_path, monkeypatch):
    from cassandra_cti.sources.ransomware_live import RansomwareLive
    src = RansomwareLive(lookback_days=3650)

    async def dead(url, headers=None):
        raise RuntimeError("host unreachable")

    monkeypatch.setattr(src, "_get_json", dead)
    # Unchanged behaviour without a mirror: logged, empty, no crash. And nothing
    # written anywhere, since no path was given.
    assert asyncio.run(src.fetch()) == []
    assert not list(tmp_path.iterdir())


def test_a_truncated_write_cannot_replace_a_good_mirror(tmp_path, monkeypatch):
    """The mirror is written beside the target and renamed: a crash halfway
    through must not leave a half-file, which is worse than none."""
    import json
    from cassandra_cti.sources.ransomware_live import RansomwareLive
    path = tmp_path / "mirror.json"
    path.write_text(json.dumps({"fetched_at": "2026-01-01T00:00:00+00:00", "backend": "v2", "records": []}))
    src = RansomwareLive(mirror_path=str(path))
    src._raw = ([{"victim": "x", "group_name": "g"}], "v2")
    monkeypatch.setattr("os.replace", lambda a, b: (_ for _ in ()).throw(OSError("disk full")))
    src._write_mirror()                   # logged, not raised
    assert json.loads(path.read_text())["fetched_at"] == "2026-01-01T00:00:00+00:00"


def test_a_network_failure_is_one_line_and_a_defect_keeps_its_traceback(tmp_path, monkeypatch, caplog):
    """Twelve stack dumps for one dropped wifi link buries the rest of the log.
    It also reads like a crash: the source lines inside those tracebacks are
    what made a dry-run marker appear in a run that was not a dry run."""
    import aiohttp

    class _Source:
        def __init__(self, name, boom):
            self.source = name
            self._boom = boom

        async def fetch(self):
            raise self._boom

    reseau = aiohttp.ClientConnectorError(
        aiohttp.client_reqrep.ConnectionKey("h", 443, True, None, None, None, None, None),
        OSError("Temporary failure in name resolution"))
    srcs = [_Source("rss:net", reseau), _Source("rss:bug", ValueError("a real defect"))]

    async def fake_build_sources(_cfg):
        return srcs

    monkeypatch.setattr(main, "build_sources", fake_build_sources)
    monkeypatch.setattr(main, "build_transport", lambda t, p: FakeTransport())
    monkeypatch.delenv("CTI_DRY_RUN", raising=False)
    with caplog.at_level(logging.ERROR):
        asyncio.run(main.run_once(_cfg(tmp_path, [{"name": "r", "transports": ["t1"]}])))

    par_source = {r.message.split(" ")[2].rstrip(":"): r for r in caplog.records
                  if r.message.startswith("Source error")}
    assert par_source["rss:net"].exc_info is None, "a DNS blip dumped a stack"
    assert par_source["rss:bug"].exc_info is not None, "a real defect lost its stack"


def test_focus_replaces_the_default_ranking_criteria():
    """In a ransomware-only channel, "prioritise ransomware-linked items"
    discriminates nothing: every item is one. The model then invents its own
    criterion, which may be sensible and is neither chosen nor repeatable."""
    from cassandra_cti.briefings import _system_prompt
    defaut = _system_prompt(5)
    assert "actively-exploited CVEs" in defaut

    cible = _system_prompt(5, "Rank by victim sector: healthcare and utilities first.")
    assert "victim sector" in cible
    assert "actively-exploited CVEs" not in cible, "focus must replace, not append"
    assert "Top 5" in cible and "numbered 1..5" in cible    # the rest is untouched

    narratif = _system_prompt(0, "Rank by blast radius.")
    assert "blast radius" in narratif and "Priorities" in narratif
    assert "actively-exploited CVEs" not in narratif

    assert _system_prompt(5, "   ") == defaut              # blank focus changes nothing
    assert _system_prompt(5, None) == defaut


def test_focus_reaches_the_model(monkeypatch):
    from cassandra_cti.briefings import _make_brief
    from types import SimpleNamespace
    seen = {}

    class _LLM:
        async def complete(self, prompt, system=None):
            seen["system"] = system
            return "ok"

    b = SimpleNamespace(name="rw", max_items=10, top_n=5,
                        focus="Rank by victim sector, healthcare first.")
    asyncio.run(_make_brief(_LLM(), b, [{"source": "s", "title": "t"}], "24h"))
    assert "victim sector, healthcare first" in seen["system"]


def test_forcing_a_briefing_on_an_empty_window_sends_nothing(tmp_path):
    """Forcing exists to test a briefing, not to post one about nothing. Asked
    to rank an empty window the model speculates about a collection gap, and
    that card alarms a reader for no reason."""
    from types import SimpleNamespace
    from cassandra_cti.briefings import run_briefings

    class _Store:
        def briefing_last_sent(self, _n):
            return None

        def events_between(self, _lo, _hi):
            return []

        def mark_briefing_sent(self, *_a):
            raise AssertionError("marked a briefing that had nothing to say")

    class _Tr:
        async def send(self, *_a, **_k):
            raise AssertionError("sent a briefing about an empty window")

    b = SimpleNamespace(name="rw", transports=["t"], schedule="24h", at=None,
                        include_sources=None, include_tags=None, include_regex=None,
                        include_terms=None, min_items=1, max_items=40, top_n=5,
                        focus=None, title=None, template=None)
    settings = SimpleNamespace(briefings=[b], llm={})
    n = asyncio.run(run_briefings(settings, _Store(), {"t": _Tr()}, force_all=True))
    assert n == 0


def test_focus_and_at_survive_the_real_config_loader(tmp_path):
    """focus and at were validated by the schema but dropped by the runtime
    BriefingDef and its parser, so getattr(b, "focus") was always None in
    production. Every focus/at test built the briefing by hand and missed it.
    This one goes through load_settings, the path a real run takes."""
    from cassandra_cti.config import load_settings
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        'schema_version: 1\nsources: {}\nroutes: []\nstore:\n  sqlite_path: "x.db"\n'
        'briefings:\n'
        '  - name: rw\n'
        '    transports: ["t"]\n'
        '    schedule: "24h"\n'
        '    at: "08:00"\n'
        '    focus: "Rank by victim sector"\n'
        '    top_n: 5\n')
    cx = tmp_path / "connectors.yaml"
    cx.write_text("connectors: []\n")
    b = load_settings(str(cfg), str(cx)).briefings[0]
    assert b.at == "08:00"
    assert b.focus == "Rank by victim sector"
