import asyncio
import queue
from datetime import datetime, timezone
from types import SimpleNamespace

from cassandra_cti.models import Event
from cassandra_cti.store import Store
from cassandra_cti.transports import REGISTRY
from cassandra_cti.transports.web import WebTransport, serialize_event
from cassandra_cti.web.app import DashboardHub, _check_auth, create_app
from cassandra_cti.web.page import DASHBOARD_PAGE


def _ev(**kw):
    kw.setdefault("source", "rss:TestFeed")
    kw.setdefault("title", "hello")
    return Event(**kw)


class _FakeServer:
    """Stands in for WebDashboardServer — no thread, no socket."""

    def __init__(self):
        self.incoming = queue.SimpleQueue()
        self.started = False
        self.db_path = None

    def start(self):
        self.started = True


def test_web_in_registry():
    assert "web" in REGISTRY
    assert REGISTRY["web"] is WebTransport


def test_serialize_event():
    ev = _ev(url="https://e/1", summary="sum", tags=["t1"],
             published_at=datetime(2025, 1, 1, tzinfo=timezone.utc))
    d = serialize_event(ev)
    assert d["source"] == "rss:TestFeed"
    assert d["title"] == "hello"
    assert d["url"] == "https://e/1"
    assert d["published_at"].startswith("2025-01-01")
    assert d["tags"] == ["t1"]


def test_dry_run_prints_and_never_starts_server(capsys, monkeypatch):
    monkeypatch.setenv("CTI_DRY_RUN", "1")
    tr = WebTransport()
    asyncio.run(tr.send([_ev()]))
    assert "[DRYRUN:WEB]" in capsys.readouterr().out
    assert tr._server is None


def test_send_pushes_serialized_events():
    tr = WebTransport()
    fake = _FakeServer()
    tr._server = fake
    asyncio.run(tr.send([_ev(title="a"), _ev(title="b")]))
    assert fake.started
    assert fake.incoming.get_nowait()["title"] == "a"
    assert fake.incoming.get_nowait()["title"] == "b"
    assert fake.incoming.empty()


def test_send_late_binds_db_path():
    tr = WebTransport(db_path="/tmp/x.db")
    fake = _FakeServer()
    tr._server = fake
    asyncio.run(tr.send([_ev()]))
    assert fake.db_path == "/tmp/x.db"


def test_store_recent_events_and_stats(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    store.upsert_event("1", "rss:A", "https://e/1", "old", "s1", "2025-01-01T00:00:00Z")
    store.upsert_event("2", "ransomware.live", "https://e/2", "new victim", "s2", "2025-06-01T00:00:00Z")
    store.upsert_event("3", "rss:A", "https://e/3", "mid", "s3", "2025-03-01T00:00:00Z")

    evs = store.recent_events()
    assert [e["id"] for e in evs] == ["2", "3", "1"]  # newest first

    only_a = store.recent_events(source="rss:A")
    assert {e["id"] for e in only_a} == {"1", "3"}

    searched = store.recent_events(q="victim")
    assert [e["id"] for e in searched] == ["2"]

    limited = store.recent_events(limit=1)
    assert len(limited) == 1 and limited[0]["id"] == "2"

    stats = store.stats()
    assert stats["total"] == 3
    assert stats["per_source"]["rss:A"] == 2
    assert stats["latest"] == "2025-06-01T00:00:00Z"


def test_hub_fanout():
    hub = DashboardHub()

    async def go():
        q1, q2 = hub.subscribe(), hub.subscribe()
        hub.publish({"title": "x"})
        assert (await q1.get())["title"] == "x"
        assert (await q2.get())["title"] == "x"
        hub.unsubscribe(q1)
        hub.publish({"title": "y"})
        assert (await q2.get())["title"] == "y"
        assert q1.empty()

    asyncio.run(go())
    assert [i["title"] for i in hub.recent] == ["x", "y"]


def test_auth_check():
    def req(headers=None, query=None):
        return SimpleNamespace(headers=headers or {}, query=query or {})

    assert _check_auth(req(), None) is True
    assert _check_auth(req(), "s3cret") is False
    assert _check_auth(req(headers={"Authorization": "Bearer s3cret"}), "s3cret") is True
    assert _check_auth(req(query={"token": "s3cret"}), "s3cret") is True
    assert _check_auth(req(query={"token": "nope"}), "s3cret") is False


def test_create_app_routes():
    app = create_app(None, None, DashboardHub())
    paths = {r.resource.canonical for r in app.router.routes()}
    assert {"/", "/api/events", "/api/stats", "/api/stream"} <= paths


def test_dashboard_page_is_self_contained():
    assert "Cassandra" in DASHBOARD_PAGE
    assert "EventSource" in DASHBOARD_PAGE
    assert "/api/stream" in DASHBOARD_PAGE
    assert "https://" not in DASHBOARD_PAGE.replace("https://e/", "")  # no CDN
