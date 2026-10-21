# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# tests/test_web_dashboard.py
#
# End-to-end rigor for the live web dashboard, the same way test_teams.py pins
# the Teams connector: every source kind serializes with the meta the UI needs,
# every source id lands in the right category, every HTTP endpoint answers and
# enforces auth, and a live event round-trips to a browser client over SSE.
#
# These are black-box tests: the real aiohttp server runs in its own thread on
# an ephemeral loopback port and is driven with stdlib urllib, so the whole
# live path (incoming queue -> pump -> hub -> SSE) is exercised, not mocked. The
# offline guard in conftest only blocks aiohttp ClientSession (outbound), which
# these tests never use.
import asyncio
import json
import socket
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

import yaml

import pytest

from cassandra_cti.models import Event, public_meta
from cassandra_cti.store import Store, _kind
from cassandra_cti.transports.web import WebTransport, serialize_event
from cassandra_cti.web.app import get_server
from cassandra_cti.web.page import DASHBOARD_PAGE

NOW = datetime(2025, 6, 1, tzinfo=timezone.utc)
ISO = NOW.isoformat()
FLAG = "\U0001F1FA\U0001F1F8"  # US flag, a functional country badge


# -- Representative event per source kind -------------------------------------
# One Event built the way its real source builds it, so the matrix tests what
# actually reaches the dashboard, not a toy payload.
def ev(kind):
    if kind == "ransomware":
        return Event(source="ransomware.live", title="ACME Corp by qilin",
                     url="https://www.ransomware.live/id/x", summary="leak",
                     published_at=NOW, tags=["ransomware"],
                     raw={"victim": "ACME Corp", "group_name": "qilin", "country": "US",
                          "country_display": "United States", "country_flag": FLAG,
                          "activity": "Manufacturing", "website": "acme.example",
                          "leak_url": "http://leak.onion/acme", "backend": "v2"})
    if kind == "vuln":
        return Event(source="cisa.kev", title="CVE-2025-1234: RCE",
                     url="https://nvd.nist.gov/vuln/detail/CVE-2025-1234", summary="exploited",
                     published_at=NOW, tags=["vulnerability", "kev", "ransomware"],
                     raw={"cve": "CVE-2025-1234", "vendor": "Acme", "product": "Gateway",
                          "due_date": "2025-07-01", "ransomware_use": True,
                          "required_action": "Patch", "date_added": "2025-06-01"})
    if kind == "ioc":
        return Event(source="abuse.ch", title="1.2.3.4:443 Emotet", url=None, summary="",
                     published_at=NOW, tags=["ioc", "c2", "emotet"],
                     raw={"ioc": "1.2.3.4:443", "ioc_type": "ip:port", "malware": "Emotet",
                          "country": "DE", "status": "online", "feed": "feodo", "confidence": 90})
    if kind == "redflag":
        return Event(source="red.flag.domains", title="42 new suspicious domains",
                     url="https://dl.red.flag.domains/daily/2025-06-01.txt", summary="",
                     published_at=NOW, tags=["redflag"],
                     raw={"file": "2025-06-01.txt", "count": 42, "date": "2025-06-01"})
    if kind == "rss":
        return Event(source="rss:Krebs on Security", title="A breach story",
                     url="https://krebsonsecurity.com/x", summary="details",
                     published_at=NOW, tags=["news", "must-read"],
                     raw={"link": "https://krebsonsecurity.com/x", "author": "bk"})
    if kind == "stats":
        return Event(source="ransomware.stats", title="Daily ransomware tracker", url=None,
                     summary="12 victims today", published_at=NOW, tags=["ransomware"],
                     raw={"stats": {"victims": 12}, "last_update": "2025-06-01", "day": "2025-06-01"})
    raise ValueError(kind)


KINDS = ["ransomware", "vuln", "ioc", "redflag", "rss", "stats"]


def _seed(store):
    for k in KINDS:
        e = ev(k)
        store.upsert_event(f"seed-{k}", e.source, e.url, e.title, e.summary, ISO,
                           tags=e.tags, meta=public_meta(e.raw))
        store.mark_delivery(f"seed-{k}", "web-dashboard", "ok")


# -- Real-server harness (thread + ephemeral loopback socket) -----------------
def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _serve(db_path=None, token=None, inventory=None, llm=None):
    port = _free_port()
    srv = get_server("127.0.0.1", port, token=token, db_path=db_path,
                     inventory=inventory, llm_cfg=llm)
    srv.start()
    if not srv.running:  # pragma: no cover - bind failure on a busy host
        pytest.skip("could not bind an ephemeral port")
    time.sleep(0.4)
    return srv, port


def _get(port, path, token=None, timeout=5):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")


def _jget(port, path, token=None):
    st, body = _get(port, path, token)
    return st, json.loads(body)


def _post(port, path, payload, token=None, timeout=5):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")


def _sse(port, pusher, want=1, token=None, timeout=6):
    """Subscribe to /api/stream, run pusher() once subscribed, collect `want`
    data payloads. The read runs in a thread so the push can interleave."""
    got = []

    def reader():
        url = f"http://127.0.0.1:{port}/api/stream" + (f"?token={token}" if token else "")
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                for raw in r:
                    line = raw.decode("utf-8").rstrip("\n")
                    if line.startswith("data: "):
                        got.append(json.loads(line[6:]))
                        if len(got) >= want:
                            break
        except Exception:  # pragma: no cover - timing/network guard
            pass

    th = threading.Thread(target=reader, daemon=True)
    th.start()
    time.sleep(0.5)  # let the SSE client subscribe before we push
    pusher()
    th.join(timeout + 1)
    return got


# -- Serialization matrix: every kind keeps the meta the UI renders -----------
def test_serialize_matrix_ransomware():
    m = serialize_event(ev("ransomware"))["meta"]
    assert m["group_name"] == "qilin"
    assert m["victim"] == "ACME Corp"
    assert m["country_display"] == "United States" and m["country_flag"] == FLAG
    assert m["activity"] == "Manufacturing"
    assert m["leak_url"] == "http://leak.onion/acme"
    assert "backend" not in m  # non-whitelisted internals never reach the browser


def test_serialize_matrix_vuln():
    m = serialize_event(ev("vuln"))["meta"]
    assert m["cve"] == "CVE-2025-1234"
    assert m["vendor"] == "Acme" and m["product"] == "Gateway"
    assert m["due_date"] == "2025-07-01"
    assert m["ransomware_use"] is True
    assert "required_action" not in m and "date_added" not in m


def test_serialize_matrix_ioc():
    m = serialize_event(ev("ioc"))["meta"]
    assert m["ioc"] == "1.2.3.4:443" and m["ioc_type"] == "ip:port"
    assert m["malware"] == "Emotet" and m["status"] == "online"
    assert m["feed"] == "feodo" and m["confidence"] == 90


def test_serialize_matrix_sparse_kinds():
    # Red flags, RSS and the stats digest carry no whitelisted meta: the UI
    # renders them from title/summary/tags. Pin that intentional contract.
    assert serialize_event(ev("redflag"))["meta"] == {}
    assert serialize_event(ev("rss"))["meta"] == {}
    assert serialize_event(ev("stats"))["meta"] == {}
    assert serialize_event(ev("rss"))["tags"] == ["news", "must-read"]


# -- Category parity: server _kind() and the page's client kind() agree -------
def test_source_kind_table():
    table = {
        "ransomware.live": "ransomware",
        "ransomware.press": "ransomware",
        "ransomware.8k": "ransomware",
        "ransomware.stats": "ransomware",
        "ransomware.pro": "ransomware",
        "red.flag.domains": "redflag",
        "cisa.kev": "vuln",
        "abuse.ch": "ioc",
        "rss:Krebs on Security": "rss",
        "rss:CERT-FR Alertes": "rss",
        "something.else": "other",
    }
    for src, cat in table.items():
        assert _kind(src) == cat, f"{src} -> {_kind(src)}, expected {cat}"


def test_client_kind_discriminators_match_server():
    # The page classifies on the client with the same discriminators the store
    # uses on the server. If one side drifts, badges and counters disagree.
    for token in ('indexOf("ransomware")', 'indexOf("red.flag")', 'indexOf("redflag")',
                  'indexOf("cisa.kev")', 'indexOf("kev")', 'indexOf("abuse.ch")',
                  'indexOf("ioc")', 'indexOf("rss:")'):
        assert token in DASHBOARD_PAGE


# -- HTTP endpoints over the real server --------------------------------------
def test_index_served():
    _, port = _serve()
    st, body = _get(port, "/")
    assert st == 200
    assert "CassandraCTI" in body and "EventSource" in body


def test_api_events_history_and_filters(tmp_path):
    db = str(tmp_path / "h.db")
    _seed(Store(db))
    _, port = _serve(db_path=db)

    st, all_ev = _jget(port, "/api/events?limit=100")
    assert st == 200 and len(all_ev["events"]) == 6
    assert {e["source"] for e in all_ev["events"]} == {ev(k).source for k in KINDS}

    _, one = _jget(port, "/api/events?source=cisa.kev")
    assert len(one["events"]) == 1 and one["events"][0]["meta"]["cve"] == "CVE-2025-1234"

    _, q = _jget(port, "/api/events?q=Emotet")
    assert len(q["events"]) == 1 and q["events"][0]["source"] == "abuse.ch"

    _, lim = _jget(port, "/api/events?limit=2")
    assert len(lim["events"]) == 2

    # The ransomware leak link and country badge survive the history round-trip.
    rw = next(e for e in all_ev["events"] if e["source"] == "ransomware.live")
    assert rw["meta"]["leak_url"] == "http://leak.onion/acme"
    assert rw["meta"]["country_flag"] == FLAG


def test_api_events_without_store_is_graceful():
    _, port = _serve(db_path=None)
    st, j = _jget(port, "/api/events")
    assert st == 200 and j["events"] == [] and "note" in j


def test_api_briefings_history_and_filters(tmp_path):
    db = str(tmp_path / "b.db")
    store = Store(db)
    store.save_briefing_output("cve-weekly", "CVE Top 10", "1. CVE-2025-1 ...",
                               item_count=12, period_label="7d")
    store.save_briefing_output("ransomware", "Ransomware Top 10", "1. ACME by qilin ...",
                               item_count=8, period_label="24h")
    store.save_briefing_output("cve-weekly", "CVE Top 10", "newest cve brief",
                               item_count=15, period_label="7d")
    _, port = _serve(db_path=db)

    st, j = _jget(port, "/api/briefings")
    assert st == 200 and len(j["briefings"]) == 3
    assert j["briefings"][0]["body"] == "newest cve brief"          # newest first
    assert j["briefings"][0]["name"] == "cve-weekly"
    assert j["briefings"][0]["item_count"] == 15

    _, only = _jget(port, "/api/briefings?name=cve-weekly")
    assert [b["body"] for b in only["briefings"]] == ["newest cve brief", "1. CVE-2025-1 ..."]

    _, lim = _jget(port, "/api/briefings?limit=1")
    assert len(lim["briefings"]) == 1


def test_api_briefings_without_store_is_graceful():
    _, port = _serve(db_path=None)
    st, j = _jget(port, "/api/briefings")
    assert st == 200 and j["briefings"] == [] and "note" in j


def test_api_stats_categories_and_deliveries(tmp_path):
    db = str(tmp_path / "s.db")
    _seed(Store(db))
    _, port = _serve(db_path=db)

    st, s = _jget(port, "/api/stats")
    assert st == 200 and s["total"] == 6
    pc = s["per_category"]
    assert pc["ransomware"] == 2  # ransomware.live + ransomware.stats
    assert pc["vuln"] == 1 and pc["ioc"] == 1
    assert pc["redflag"] == 1 and pc["rss"] == 1
    assert s["deliveries"]["sent_ok"] == 6
    assert len(s["activity"]) == 30 and len(s["activity_hourly"]) == 24
    assert set(s["windows"].keys()) == {"24h", "7d", "30d"}
    assert s["live_clients"] == 0


def test_api_meta_inventory_and_llm():
    _, port = _serve(inventory={"enabled": True, "match_mode": "filter", "terms": ["ACME", "Gov"]},
                     llm={"enabled": False})
    st, m = _jget(port, "/api/meta")
    assert st == 200
    assert m["inventory"]["enabled"] is True
    assert m["inventory"]["mode"] == "filter"
    assert m["inventory"]["terms"] == ["ACME", "Gov"]
    assert m["llm"]["enabled"] is False


def test_api_ai_summarize_disabled_is_503():
    _, port = _serve(llm={"enabled": False})
    st, _body = _post(port, "/api/ai/summarize", {"event": {"title": "x"}})
    assert st == 503


def test_api_ai_summarize_enabled_empty_event_is_400():
    # LLM on, but an empty event is rejected before any provider is contacted.
    _, port = _serve(llm={"enabled": True, "provider": "ollama"})
    st, _body = _post(port, "/api/ai/summarize", {"event": {}})
    assert st == 400


# -- Auth matrix: a token shuts every door ------------------------------------
def test_auth_required_on_every_endpoint(tmp_path):
    db = str(tmp_path / "a.db")
    _seed(Store(db))
    tok = "s3cret"
    _, port = _serve(db_path=db, token=tok, llm={"enabled": False})

    # No token: every endpoint refuses. /api/stream rejects before it streams,
    # so the GET returns promptly rather than hanging.
    for path in ("/", "/api/events", "/api/briefings", "/api/stats", "/api/meta", "/api/stream"):
        st, _b = _get(port, path)
        assert st == 401, f"{path} unauth status {st}"
    st, _b = _post(port, "/api/ai/summarize", {"event": {"title": "x"}})
    assert st == 401

    # A Bearer header opens the data endpoints (not /api/stream: it would block).
    for path in ("/", "/api/events", "/api/briefings", "/api/stats", "/api/meta"):
        st, _b = _get(port, path, token=tok)
        assert st == 200, f"{path} authed status {st}"

    # The ?token= query string works too, and a wrong one is still refused.
    assert _jget(port, f"/api/stats?token={tok}")[0] == 200
    assert _get(port, "/api/stats?token=wrong")[0] == 401


def test_check_auth_token_edges():
    # Unit-level edges for the constant-time token check: no crash on a
    # non-ASCII token, and malformed/empty Authorization headers are refused.
    from cassandra_cti.web.app import _check_auth

    class _Req:
        def __init__(self, auth=None, qtoken=None):
            self.headers = {} if auth is None else {"Authorization": auth}
            self.query = {} if qtoken is None else {"token": qtoken}

    tok = "s3cr3t-Token_\u00e9"  # trailing char is non-ASCII on purpose
    assert _check_auth(_Req(), None) is True                       # no token -> open
    assert _check_auth(_Req(auth=f"Bearer {tok}"), tok) is True    # correct bearer
    assert _check_auth(_Req(qtoken=tok), tok) is True              # correct ?token=
    assert _check_auth(_Req(auth="Bearer nope"), tok) is False     # wrong bearer
    assert _check_auth(_Req(qtoken="nope"), tok) is False          # wrong ?token=
    assert _check_auth(_Req(), tok) is False                       # no creds
    assert _check_auth(_Req(auth=tok), tok) is False               # missing "Bearer "
    assert _check_auth(_Req(auth="Bearer "), tok) is False         # empty bearer


# -- SSE: a published event reaches a connected client ------------------------
def test_sse_delivers_published_event():
    srv, port = _serve(db_path=None)
    got = _sse(port, lambda: srv.incoming.put(serialize_event(ev("ioc"))), want=1)
    assert got, "no event arrived over SSE"
    assert got[0]["source"] == "abuse.ch"
    assert got[0]["meta"]["ioc"] == "1.2.3.4:443"


def test_live_send_round_trips_through_web_transport(tmp_path):
    srv, port = _serve(db_path=str(tmp_path / "live.db"))

    def push():
        tr = WebTransport(host="127.0.0.1", port=port)
        tr._server = srv  # reuse the already-started server
        asyncio.run(tr.send([ev("ransomware")]))

    got = _sse(port, push, want=1)
    assert got, "no event arrived over the real SSE socket"
    assert got[0]["source"] == "ransomware.live"
    assert got[0]["meta"]["group_name"] == "qilin"
    assert got[0]["meta"]["country_flag"] == FLAG


# -- The page only linkifies http(s): no click-to-run javascript: URLs --------
def test_page_guards_unsafe_link_schemes():
    assert "function safeUrl(u)" in DASHBOARD_PAGE
    assert "safeUrl(e.url)" in DASHBOARD_PAGE
    assert "safeUrl(m.leak_url)" in DASHBOARD_PAGE
    # The old unguarded href patterns must be gone.
    assert "esc(e.url)" not in DASHBOARD_PAGE
    assert "esc(m.leak_url)" not in DASHBOARD_PAGE


# -- Full pipeline: run_once routes every event to the dashboard --------------
class _FakePipelineSource:
    def __init__(self, source, events):
        self.source = source
        self._events = events

    async def fetch(self):
        return list(self._events)


def test_run_once_routes_all_events_to_dashboard(tmp_path, monkeypatch):
    """`cassandra run --web` builds a web transport and a catch-all route. Drive
    run_once the same way, with the real WebTransport, and assert every source's
    event reaches the live dashboard and that db/inventory/llm are late-bound."""
    import cassandra_cti.main as main
    from cassandra_cti.config import RouteDef, TransportDef

    port = _free_port()
    cfg = tmp_path / "config.yaml"
    cfg.write_text(yaml.safe_dump({
        "schema_version": 1,
        "sources": {},
        "transports": {},
        "routes": [],
        "store": {"sqlite_path": "pipe.db"},
        "metrics": {"enabled": False},
        "inventory": {"enabled": True, "match_mode": "highlight", "terms": ["ACME"]},
        "llm": {"enabled": False, "provider": "auto"},
    }))

    built = {}

    class _OtherTransport:
        def __init__(self):
            self.batch_cfg = {}

        async def send(self, *a, **k):
            pass

        async def aclose(self):
            pass

    def fake_build_transport(ttype, params):
        if ttype == "web":
            tr = WebTransport(host="127.0.0.1", port=port)
            built["web"] = tr
            return tr
        return _OtherTransport()

    async def fake_build_sources(_cfg):
        return [_FakePipelineSource("ransomware.live", [ev("ransomware")]),
                _FakePipelineSource("cisa.kev", [ev("vuln")]),
                _FakePipelineSource("abuse.ch", [ev("ioc")])]

    monkeypatch.setattr(main, "build_transport", fake_build_transport)
    monkeypatch.setattr(main, "build_sources", fake_build_sources)
    monkeypatch.delenv("CTI_DRY_RUN", raising=False)

    extra_t = [TransportDef(id="web-dashboard", type="web",
                            params={"host": "127.0.0.1", "port": port})]
    extra_r = [RouteDef(name="web-dashboard", include_regex=".", transports=["web-dashboard"])]
    asyncio.run(main.run_once(str(cfg), extra_transports=extra_t, extra_routes=extra_r))

    tr = built["web"]
    # ensure_started() bound the server; the late-binding wired db/inventory/llm.
    assert tr._server is not None and tr._server.running
    assert tr.db_path and tr.db_path.endswith("pipe.db")
    assert tr.inventory.get("enabled") is True
    assert tr.llm.get("enabled") is False
    # The catch-all route delivered every source's event to the dashboard.
    time.sleep(0.6)  # let the pump drain incoming -> hub
    seen = {item["source"] for item in list(tr._server.hub.recent)}
    assert {"ransomware.live", "cisa.kev", "abuse.ch"} <= seen
