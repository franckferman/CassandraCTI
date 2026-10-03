"""Behavioural tests for cassandra_cti.main.run_once.

Modeled on test_dryrun.py: FakeSource/FakeTransport, monkeypatched
build_sources/build_transport, a tmp config file, metrics disabled and no
network (the conftest _no_network autouse guard makes any real request raise).
"""
import asyncio
import sqlite3
from datetime import datetime, timezone

import yaml

import cassandra_cti.main as main
from cassandra_cti.models import Event


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
        self.sent.append({
            "chunk": list(chunk),
            "title": title,
            "template_text": template_text,
        })

    async def aclose(self):
        pass


def _cfg(tmp_path, routes, filters=None):
    data = {
        "schema_version": 1,
        "sources": {},
        "transports": {"teams": [{"id": "t1", "webhook_url": "http://x"}]},
        "routes": routes,
        "store": {"sqlite_path": "cti.db"},
        "metrics": {"enabled": False},
        "filters": filters or {},
    }
    cfg = tmp_path / "config.yaml"
    cfg.write_text(yaml.safe_dump(data))
    return str(cfg)


def _db(tmp_path):
    return str(tmp_path / "cti.db")


def _run(cfg, monkeypatch, sources, batch_cfg=None, only_sources=None):
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
    asyncio.run(main.run_once(cfg, only_sources=only_sources))
    return built


def _sent_events(tr):
    return [ev for call in tr.sent for ev in call["chunk"]]


def _sent_titles(tr):
    return [ev.title for ev in _sent_events(tr)]


def _sent_sources(tr):
    return {ev.source for ev in _sent_events(tr)}


def _events(n, source="rss:X"):
    return [Event(source=source, title=f"t{i}", url=f"https://e/{i}") for i in range(n)]


def _deliveries_ok(db_path):
    con = sqlite3.connect(db_path)
    try:
        return con.execute(
            "SELECT COUNT(*) FROM deliveries WHERE status='ok'"
        ).fetchone()[0]
    finally:
        con.close()


def _route(**kw):
    kw.setdefault("transports", ["t1"])
    return kw


# --- title deny filter --------------------------------------------------------

def test_title_deny_filter_drops_matches_case_insensitive(tmp_path, monkeypatch):
    events = [
        Event(source="rss:X", title="Sponsored ad", url="https://e/1"),
        Event(source="rss:X", title="Critical CVE-2025-1", url="https://e/2"),
        Event(source="rss:X", title="SPONSORED deal", url="https://e/3"),
    ]
    cfg = _cfg(
        tmp_path,
        routes=[_route(name="all", include_sources=["rss:"])],
        filters={"title_regex_deny": ["sponsored"]},
    )
    built = _run(cfg, monkeypatch, [("rss:", events)])
    assert _sent_titles(built[0]) == ["Critical CVE-2025-1"]


# --- title allow filter -------------------------------------------------------

def test_title_allow_filter_only_matches_pass(tmp_path, monkeypatch):
    events = [
        Event(source="rss:X", title="New CVE alert", url="https://e/1"),
        Event(source="rss:X", title="Random news", url="https://e/2"),
    ]
    cfg = _cfg(
        tmp_path,
        routes=[_route(name="all", include_sources=["rss:"])],
        filters={"title_regex_allow": ["cve"]},
    )
    built = _run(cfg, monkeypatch, [("rss:", events)])
    assert _sent_titles(built[0]) == ["New CVE alert"]


def test_title_allow_and_deny_compose(tmp_path, monkeypatch):
    events = [
        Event(source="rss:X", title="CVE alert", url="https://e/1"),
        Event(source="rss:X", title="Sponsored CVE roundup", url="https://e/2"),
        Event(source="rss:X", title="Random news", url="https://e/3"),
    ]
    cfg = _cfg(
        tmp_path,
        routes=[_route(name="all", include_sources=["rss:"])],
        filters={"title_regex_allow": ["cve"], "title_regex_deny": ["sponsored"]},
    )
    built = _run(cfg, monkeypatch, [("rss:", events)])
    assert _sent_titles(built[0]) == ["CVE alert"]


# --- max_items_per_source cap -------------------------------------------------

def test_max_items_per_source_caps_per_event_source(tmp_path, monkeypatch):
    events = [
        Event(source="rss:A", title="a1", url="https://e/a1"),
        Event(source="rss:A", title="a2", url="https://e/a2"),
        Event(source="rss:A", title="a3", url="https://e/a3"),
        Event(source="rss:B", title="b1", url="https://e/b1"),
        Event(source="rss:B", title="b2", url="https://e/b2"),
        Event(source="rss:B", title="b3", url="https://e/b3"),
    ]
    cfg = _cfg(
        tmp_path,
        routes=[_route(name="all", include_sources=["rss:"])],
        filters={"max_items_per_source": 2},
    )
    built = _run(cfg, monkeypatch, [("rss:", events)])
    assert _sent_titles(built[0]) == ["a1", "a2", "b1", "b2"]


# --- since filter via CTI_SINCE -----------------------------------------------

def test_since_filter_drops_old_keeps_none_and_treats_naive_as_utc(tmp_path, monkeypatch):
    events = [
        Event(source="rss:X", title="old", url="https://e/old",
              published_at=datetime(2025, 1, 1)),
        Event(source="rss:X", title="new", url="https://e/new",
              published_at=datetime(2026, 6, 1)),
        Event(source="rss:X", title="none", url="https://e/none",
              published_at=None),
        Event(source="rss:X", title="awold", url="https://e/awold",
              published_at=datetime(2025, 1, 1, tzinfo=timezone.utc)),
    ]
    cfg = _cfg(tmp_path, routes=[_route(name="all", include_sources=["rss:"])])
    monkeypatch.setenv("CTI_SINCE", "2026-01-01")
    built = _run(cfg, monkeypatch, [("rss:", events)])
    assert set(_sent_titles(built[0])) == {"new", "none"}


# --- batching (route without template) ----------------------------------------

def test_batching_chunks_without_template(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, routes=[_route(name="all", include_sources=["rss:"])])
    built = _run(
        cfg, monkeypatch, [("rss:", _events(12))],
        batch_cfg={"enabled": True, "max_items": 5},
    )
    sizes = [len(call["chunk"]) for call in built[0].sent]
    assert sizes == [5, 5, 2]
    assert _deliveries_ok(_db(tmp_path)) == 12


# --- templated route must not batch-drop events -------------------------------

def test_templated_route_sends_one_per_message_no_loss(tmp_path, monkeypatch):
    tpl = tmp_path / "tpl.j2"
    tpl.write_text("HELLO {{ x }}")
    cfg = _cfg(
        tmp_path,
        routes=[_route(name="all", include_sources=["rss:"], template=str(tpl))],
    )
    built = _run(
        cfg, monkeypatch, [("rss:", _events(12))],
        batch_cfg={"enabled": True, "max_items": 5},
    )
    assert len(built[0].sent) == 12
    assert all(len(call["chunk"]) == 1 for call in built[0].sent)
    assert all(call["template_text"] == "HELLO {{ x }}" for call in built[0].sent)
    assert _deliveries_ok(_db(tmp_path)) == 12


# --- dedup --------------------------------------------------------------------

def test_dedup_persists_and_no_dedupe_bypasses(tmp_path, monkeypatch):
    ev = Event(source="rss:X", title="t", url="https://e/1")
    cfg = _cfg(tmp_path, routes=[_route(name="all", include_sources=["rss:"])])

    first = _run(cfg, monkeypatch, [("rss:", [ev])])
    assert len(_sent_events(first[0])) == 1
    assert _deliveries_ok(_db(tmp_path)) == 1

    second = _run(cfg, monkeypatch, [("rss:", [ev])])
    assert len(_sent_events(second[0])) == 0

    monkeypatch.setenv("CTI_NO_DEDUPE", "1")
    third = _run(cfg, monkeypatch, [("rss:", [ev])])
    assert len(_sent_events(third[0])) == 1


# --- in-run same-transport dedup ----------------------------------------------

def test_shared_transport_delivered_once_per_run(tmp_path, monkeypatch):
    ev = Event(source="rss:X", title="CVE thing", url="https://e/1")
    cfg = _cfg(
        tmp_path,
        routes=[
            _route(name="bysource", include_sources=["rss:"]),
            _route(name="byregex", include_regex="(?i)cve"),
        ],
    )
    built = _run(cfg, monkeypatch, [("rss:", [ev])])
    assert len(built[0].sent) == 1
    assert len(_sent_events(built[0])) == 1
    assert _deliveries_ok(_db(tmp_path)) == 1


# --- template loading ---------------------------------------------------------

def test_template_file_text_passed_to_send(tmp_path, monkeypatch):
    tpl = tmp_path / "tpl.j2"
    tpl.write_text("BODY {{ title }}")
    cfg = _cfg(
        tmp_path,
        routes=[_route(name="all", include_sources=["rss:"], template=str(tpl))],
    )
    ev = Event(source="rss:X", title="t", url="https://e/1")
    built = _run(cfg, monkeypatch, [("rss:", [ev])])
    assert len(built[0].sent) == 1
    assert built[0].sent[0]["template_text"] == "BODY {{ title }}"
    assert _deliveries_ok(_db(tmp_path)) == 1


def test_missing_template_warns_but_still_sends(tmp_path, monkeypatch):
    missing = str(tmp_path / "nope.j2")
    cfg = _cfg(
        tmp_path,
        routes=[_route(name="all", include_sources=["rss:"], template=missing)],
    )
    ev = Event(source="rss:X", title="t", url="https://e/1")
    built = _run(cfg, monkeypatch, [("rss:", [ev])])
    assert len(built[0].sent) == 1
    assert built[0].sent[0]["template_text"] is None
    assert _deliveries_ok(_db(tmp_path)) == 1


# --- only_sources filter ------------------------------------------------------

def test_only_sources_keeps_prefix_and_exact_matches(tmp_path, monkeypatch):
    sources = [
        ("rss:Krebs", [Event(source="rss:Krebs", title="krebs", url="https://e/k")]),
        ("ransomware.live", [Event(source="ransomware.live", title="rw", url="https://e/r")]),
        ("red.flag.domains", [Event(source="red.flag.domains", title="rfd", url="https://e/d")]),
    ]
    cfg = _cfg(
        tmp_path,
        routes=[_route(
            name="all",
            include_sources=["rss:", "ransomware.live", "red.flag.domains"],
        )],
    )
    built = _run(
        cfg, monkeypatch, sources,
        only_sources=["rss:", "ransomware.live"],
    )
    assert _sent_sources(built[0]) == {"rss:Krebs", "ransomware.live"}
