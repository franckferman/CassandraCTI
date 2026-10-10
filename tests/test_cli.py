"""CLI command tests (offline only).

Every test points --config/--connectors at files under ``tmp_path`` and an
autouse fixture redirects ``cassandra_cti.cli.default_dir`` into ``tmp_path`` as
well, so the real user config directory is never created or touched. Networked
transports are never built (backfill patches the builder); the autouse
``_no_network`` guard in conftest turns any accidental real request into a
loud failure.
"""
import sqlite3

import pytest
import yaml
from typer.testing import CliRunner

from cassandra_cti.cli import app
from cassandra_cti.store import Store
from cassandra_cti.util import make_event_id, resolve_db_path

runner = CliRunner()


@pytest.fixture(autouse=True)
def _fake_default_dir(monkeypatch, tmp_path):
    """Never let a command resolve paths inside the real default_dir()."""
    appdir = tmp_path / "appdir"
    monkeypatch.setattr("cassandra_cti.cli.default_dir", lambda: appdir)
    return appdir


def _read_yaml(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _write_yaml(path, data):
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f)


# --------------------------------------------------------------------------- #
# init
# --------------------------------------------------------------------------- #
def test_init_creates_then_reports_exists(tmp_path):
    cfg = tmp_path / "config.yaml"
    cx = tmp_path / "connectors.yaml"

    r1 = runner.invoke(app, ["init", "--config", str(cfg), "--connectors", str(cx)])
    assert r1.exit_code == 0, r1.output
    assert "Created" in r1.output
    assert cfg.exists()
    assert cx.exists()

    r2 = runner.invoke(app, ["init", "--config", str(cfg), "--connectors", str(cx)])
    assert r2.exit_code == 0, r2.output
    assert "Exists" in r2.output


# --------------------------------------------------------------------------- #
# quickstart
# --------------------------------------------------------------------------- #
def test_quickstart_no_web_scaffolds(tmp_path):
    cfg = tmp_path / "config.yaml"
    cx = tmp_path / "connectors.yaml"
    r = runner.invoke(app, ["quickstart", "--no-web", "--config", str(cfg), "--connectors", str(cx)])
    assert r.exit_code == 0, r.output
    assert cfg.exists() and cx.exists()
    assert "Config ready" in r.output


def test_config_roundtrip_stays_strict_parseable(tmp_path):
    """init copies the shipped example (flow-style feeds with '?' in URLs); a
    subsequent edit must not emit YAML that a strict parser (PyYAML) rejects."""
    cfg = tmp_path / "config.yaml"
    cx = tmp_path / "connectors.yaml"
    assert runner.invoke(app, ["init", "--config", str(cfg), "--connectors", str(cx)]).exit_code == 0
    edit = runner.invoke(app, ["add-source", "kev", "--config", str(cfg)])
    assert edit.exit_code == 0, edit.output
    # _read_yaml uses PyYAML safe_load -> raises if the round-trip broke quoting.
    data = _read_yaml(cfg)
    assert data["sources"]["cisa_kev"]["enabled"] is True


# --------------------------------------------------------------------------- #
# add-source
# --------------------------------------------------------------------------- #
def test_add_source_rss_requires_name_and_url(tmp_path):
    cfg = tmp_path / "config.yaml"

    missing_name = runner.invoke(app, ["add-source", "rss", "--url", "https://x/f", "--config", str(cfg)])
    assert missing_name.exit_code != 0

    missing_url = runner.invoke(app, ["add-source", "rss", "--name", "X", "--config", str(cfg)])
    assert missing_url.exit_code != 0

    assert not cfg.exists()


def test_add_source_rss_adds_and_dedupes(tmp_path):
    cfg = tmp_path / "config.yaml"
    url = "https://feeds.example/rss"

    r = runner.invoke(app, ["add-source", "rss", "--name", "Foo", "--url", url, "--tags", "a,b", "--config", str(cfg)])
    assert r.exit_code == 0, r.output
    feeds = _read_yaml(cfg)["sources"]["rss"]["feeds"]
    assert len(feeds) == 1
    assert feeds[0]["url"] == url
    assert feeds[0]["tags"] == ["a", "b"]

    dup = runner.invoke(app, ["add-source", "rss", "--name", "FooBis", "--url", url, "--config", str(cfg)])
    assert dup.exit_code == 0, dup.output
    assert "Already present" in dup.output
    assert len(_read_yaml(cfg)["sources"]["rss"]["feeds"]) == 1


def test_add_source_ransomware_live_sets_enabled(tmp_path):
    cfg = tmp_path / "config.yaml"
    r = runner.invoke(app, ["add-source", "ransomware_live", "--config", str(cfg)])
    assert r.exit_code == 0, r.output
    assert _read_yaml(cfg)["sources"]["ransomware_live"]["enabled"] is True


def test_add_source_redflag_sets_enabled(tmp_path):
    cfg = tmp_path / "config.yaml"
    r = runner.invoke(app, ["add-source", "redflag", "--config", str(cfg)])
    assert r.exit_code == 0, r.output
    assert _read_yaml(cfg)["sources"]["red_flag_domains"]["enabled"] is True


def test_add_source_unknown_kind_errors(tmp_path):
    cfg = tmp_path / "config.yaml"
    r = runner.invoke(app, ["add-source", "bogus", "--config", str(cfg)])
    assert r.exit_code != 0
    assert not cfg.exists()


def test_add_source_kev_sets_enabled(tmp_path):
    cfg = tmp_path / "config.yaml"
    r = runner.invoke(app, ["add-source", "kev", "--config", str(cfg)])
    assert r.exit_code == 0, r.output
    assert _read_yaml(cfg)["sources"]["cisa_kev"]["enabled"] is True


def test_add_source_abusech_feeds_and_key(tmp_path):
    cfg = tmp_path / "config.yaml"
    r = runner.invoke(app, ["add-source", "abusech", "--feeds", "feodo,threatfox",
                            "--api-key", "SECRET", "--config", str(cfg)])
    assert r.exit_code == 0, r.output
    s = _read_yaml(cfg)["sources"]["abusech"]
    assert s["enabled"] is True
    assert s["feeds"] == ["feodo", "threatfox"]
    assert s["api_key"] == "SECRET"


# --------------------------------------------------------------------------- #
# list
# --------------------------------------------------------------------------- #
def test_list_surfaces_all_sources_without_leaking_keys(tmp_path):
    cfg = tmp_path / "config.yaml"
    cx = tmp_path / "connectors.yaml"
    _write_yaml(cfg, {
        "schema_version": 1,
        "sources": {
            "rss": {"enabled": True, "feeds": [{"name": "Krebs", "url": "https://k/f", "tags": ["news"]}]},
            "cisa_kev": {"enabled": True, "lookback_days": 365},
            "abusech": {"enabled": True, "feeds": ["feodo"], "api_key": "SUPERSECRET"},
            "ransomware_live": {"enabled": False},
        },
        "routes": [],
    })
    _write_yaml(cx, {"connectors": [{"id": "d1", "type": "discord", "params": {}}]})

    r = runner.invoke(app, ["list", "--config", str(cfg), "--connectors", str(cx)])
    assert r.exit_code == 0, r.output
    # every source kind is surfaced, with on/off state
    assert "rss (1 feeds)" in r.output
    assert "cisa_kev" in r.output and "abusech" in r.output
    assert "[on ] cisa_kev" in r.output
    assert "[off] ransomware_live" in r.output
    # a literal api_key is reported as set but NEVER printed
    assert "api_key=set" in r.output
    assert "SUPERSECRET" not in r.output


# --------------------------------------------------------------------------- #
# add-connector (all transport types)
# --------------------------------------------------------------------------- #
def test_add_connector_types_and_validation(tmp_path):
    cx = tmp_path / "connectors.yaml"

    runner.invoke(app, ["add-connector", "--id", "tm", "--type", "teams",
                        "--webhook-url", "https://x/teams", "--connectors", str(cx)])
    runner.invoke(app, ["add-connector", "--id", "dc", "--type", "discord",
                        "--webhook-url", "https://x/dc", "--username", "Bot", "--connectors", str(cx)])
    runner.invoke(app, ["add-connector", "--id", "tg", "--type", "telegram",
                        "--bot-token", "1:AA", "--chat-id", "@c", "--connectors", str(cx)])
    runner.invoke(app, ["add-connector", "--id", "mail", "--type", "smtp", "--host", "localhost",
                        "--from-addr", "a@b.c", "--to-addrs", "x@y.z", "--connectors", str(cx)])
    runner.invoke(app, ["add-connector", "--id", "web", "--type", "web",
                        "--dashboard-port", "9000", "--token", "sek", "--connectors", str(cx)])

    conns = {c["id"]: c for c in _read_yaml(cx)["connectors"]}
    assert conns["web"]["type"] == "web"
    assert conns["web"]["params"]["port"] == 9000 and conns["web"]["params"]["host"] == "127.0.0.1"
    assert conns["web"]["params"]["token"] == "sek"
    assert conns["tm"]["type"] == "teams"
    assert conns["tm"]["params"]["webhook_url"] == "https://x/teams"
    assert conns["dc"]["type"] == "discord" and conns["dc"]["params"]["username"] == "Bot"
    assert conns["tg"]["type"] == "telegram" and conns["tg"]["params"]["chat_id"] == "@c"
    assert conns["mail"]["type"] == "smtp" and conns["mail"]["params"]["to_addrs"] == "x@y.z"

    # missing required params -> non-zero exit, nothing added
    bad = runner.invoke(app, ["add-connector", "--id", "tg2", "--type", "telegram",
                              "--bot-token", "1:AA", "--connectors", str(cx)])
    assert bad.exit_code != 0
    assert "tg2" not in {c["id"] for c in _read_yaml(cx)["connectors"]}


# --------------------------------------------------------------------------- #
# remove-source
# --------------------------------------------------------------------------- #
def test_remove_source_rss_by_name_then_url(tmp_path):
    cfg = tmp_path / "config.yaml"
    runner.invoke(app, ["add-source", "rss", "--name", "A", "--url", "https://a/f", "--config", str(cfg)])
    runner.invoke(app, ["add-source", "rss", "--name", "B", "--url", "https://b/f", "--config", str(cfg)])

    r = runner.invoke(app, ["remove-source", "rss", "--name", "A", "--config", str(cfg)])
    assert r.exit_code == 0, r.output
    assert [f["url"] for f in _read_yaml(cfg)["sources"]["rss"]["feeds"]] == ["https://b/f"]

    r2 = runner.invoke(app, ["remove-source", "rss", "--url", "https://b/f", "--config", str(cfg)])
    assert r2.exit_code == 0, r2.output
    assert _read_yaml(cfg)["sources"]["rss"]["feeds"] == []


def test_remove_source_rss_requires_selector(tmp_path):
    cfg = tmp_path / "config.yaml"
    _write_yaml(cfg, {"schema_version": 1, "sources": {"rss": {"enabled": True, "feeds": []}}})
    r = runner.invoke(app, ["remove-source", "rss", "--config", str(cfg)])
    assert r.exit_code != 0


def test_remove_source_disables_other_source(tmp_path):
    cfg = tmp_path / "config.yaml"
    runner.invoke(app, ["add-source", "kev", "--config", str(cfg)])
    assert _read_yaml(cfg)["sources"]["cisa_kev"]["enabled"] is True
    r = runner.invoke(app, ["remove-source", "kev", "--config", str(cfg)])
    assert r.exit_code == 0, r.output
    assert _read_yaml(cfg)["sources"]["cisa_kev"]["enabled"] is False


# --------------------------------------------------------------------------- #
# import-feeds
# --------------------------------------------------------------------------- #
def test_import_feeds(tmp_path):
    cfg = tmp_path / "config.yaml"
    seed = runner.invoke(app, ["add-source", "rss", "--name", "Existing", "--url", "https://exists.example/feed", "--config", str(cfg)])
    assert seed.exit_code == 0, seed.output

    csv_file = tmp_path / "feeds.csv"
    csv_file.write_text("New1,https://new1.example/feed,a|b\nExisting,https://exists.example/feed,x\nSolo\nNew2,https://new2.example/feed\n", encoding="utf-8")

    r = runner.invoke(app, ["import-feeds", str(csv_file), "--config", str(cfg)])
    assert r.exit_code == 0, r.output
    assert "2 feeds added" in r.output
    assert "Skip (already exists): Existing" in r.output

    feeds = _read_yaml(cfg)["sources"]["rss"]["feeds"]
    assert len(feeds) == 3
    by_url = {f["url"]: f for f in feeds}
    assert by_url["https://new1.example/feed"]["tags"] == ["a", "b"]
    assert by_url["https://new2.example/feed"]["tags"] == []


def test_import_feeds_missing_file_errors(tmp_path):
    cfg = tmp_path / "config.yaml"
    r = runner.invoke(app, ["import-feeds", str(tmp_path / "nope.csv"), "--config", str(cfg)])
    assert r.exit_code != 0


# --------------------------------------------------------------------------- #
# routes-add
# --------------------------------------------------------------------------- #
def test_routes_add_populates_and_replaces(tmp_path):
    cfg = tmp_path / "config.yaml"
    tpl = tmp_path / "tpl.j2"

    r = runner.invoke(app, ["routes-add", "--name", "r1", "--transports", "t1,t2", "--include", "rss:", "--include-tag", "cert", "--include-regex", "foo.*", "--template", str(tpl), "--config", str(cfg)])
    assert r.exit_code == 0, r.output
    routes = _read_yaml(cfg)["routes"]
    assert len(routes) == 1
    route = routes[0]
    assert route["transports"] == ["t1", "t2"]
    assert route["include_sources"] == ["rss:"]
    assert route["include_tags"] == ["cert"]
    assert route["include_regex"] == "foo.*"
    assert route["template"] == str(tpl)

    again = runner.invoke(app, ["routes-add", "--name", "r1", "--transports", "t3", "--config", str(cfg)])
    assert again.exit_code == 0, again.output
    routes2 = _read_yaml(cfg)["routes"]
    assert len(routes2) == 1
    assert routes2[0]["transports"] == ["t3"]
    assert "include_sources" not in routes2[0]


# --------------------------------------------------------------------------- #
# briefings
# --------------------------------------------------------------------------- #
def test_briefing_add(tmp_path):
    cfg = tmp_path / "config.yaml"
    r = runner.invoke(app, ["briefing-add", "--name", "vuln-daily", "--transports", "d1",
                            "--include", "cisa.kev", "--schedule", "12h", "--config", str(cfg)])
    assert r.exit_code == 0, r.output
    b = _read_yaml(cfg)["briefings"][0]
    assert b["name"] == "vuln-daily"
    assert b["transports"] == ["d1"]
    assert b["include_sources"] == ["cisa.kev"]
    assert b["schedule"] == "12h"


def test_routes_add_include_terms(tmp_path):
    cfg = tmp_path / "config.yaml"
    r = runner.invoke(app, ["routes-add", "--name", "entity", "--transports", "signal-soc",
                            "--include-terms", "Credit Agricole, Gouvernement", "--config", str(cfg)])
    assert r.exit_code == 0, r.output
    route = _read_yaml(cfg)["routes"][0]
    assert route["include_terms"] == ["Credit Agricole", "Gouvernement"]


def test_briefing_add_include_terms(tmp_path):
    cfg = tmp_path / "config.yaml"
    r = runner.invoke(app, ["briefing-add", "--name", "watch", "--transports", "d1",
                            "--include-terms", "BNP,Credit Agricole", "--config", str(cfg)])
    assert r.exit_code == 0, r.output
    assert _read_yaml(cfg)["briefings"][0]["include_terms"] == ["BNP", "Credit Agricole"]


def test_briefing_add_top_n(tmp_path):
    cfg = tmp_path / "config.yaml"
    r = runner.invoke(app, ["briefing-add", "--name", "cve-daily", "--transports", "d1",
                            "--include", "cisa.kev", "--top-n", "10", "--config", str(cfg)])
    assert r.exit_code == 0, r.output
    assert _read_yaml(cfg)["briefings"][0]["top_n"] == 10


def test_list_shows_briefings(tmp_path):
    cfg = tmp_path / "config.yaml"
    cx = tmp_path / "connectors.yaml"
    _write_yaml(cfg, {"schema_version": 1, "sources": {}, "routes": [],
                      "briefings": [{"name": "b1", "transports": ["d1"], "schedule": "24h",
                                     "include_sources": ["cisa.kev"]}]})
    _write_yaml(cx, {"connectors": []})
    r = runner.invoke(app, ["list", "--config", str(cfg), "--connectors", str(cx)])
    assert r.exit_code == 0, r.output
    assert "Briefings:" in r.output and "b1" in r.output


def test_briefing_run_dry_run(tmp_path):
    cfg = tmp_path / "config.yaml"
    cx = tmp_path / "connectors.yaml"
    _write_yaml(cfg, {"schema_version": 1, "store": {"sqlite_path": "b.db"},
                      "sources": {"cisa_kev": {"enabled": True}},
                      "transports": {"use": ["d1"]},
                      "briefings": [{"name": "vuln", "transports": ["d1"],
                                     "include_sources": ["cisa.kev"], "min_items": 1}]})
    _write_yaml(cx, {"connectors": [{"id": "d1", "type": "discord",
                                     "params": {"webhook_url": "http://x/h"}}]})
    db = resolve_db_path("b.db", str(cfg))
    st = Store(db)
    st.upsert_event(make_event_id("cisa.kev", "https://n/1", "c1"), "cisa.kev",
                    "https://n/1", "c1", "s", None, tags=["vulnerability"], meta={"cve": "CVE-1"})

    r = runner.invoke(app, ["briefing-run", "--all", "--dry-run",
                            "--config", str(cfg), "--connectors", str(cx)])
    assert r.exit_code == 0, r.output
    assert "[DRYRUN:BRIEFING]" in r.output
    assert "Briefings sent: 1" in r.output


def test_briefing_run_unknown_name_errors(tmp_path):
    cfg = tmp_path / "config.yaml"
    _write_yaml(cfg, {"schema_version": 1, "briefings": [{"name": "a", "transports": ["d1"]}]})
    r = runner.invoke(app, ["briefing-run", "--name", "nope", "--config", str(cfg)])
    assert r.exit_code != 0


# --------------------------------------------------------------------------- #
# CRUD: auto-activation + removes
# --------------------------------------------------------------------------- #
def test_routes_add_auto_activates_transports_use(tmp_path):
    cfg = tmp_path / "config.yaml"
    r = runner.invoke(app, ["routes-add", "--name", "r1", "--transports", "d1,d2",
                            "--include", "rss:", "--config", str(cfg)])
    assert r.exit_code == 0, r.output
    assert _read_yaml(cfg)["transports"]["use"] == ["d1", "d2"]


def test_briefing_add_auto_activates_transports_use(tmp_path):
    cfg = tmp_path / "config.yaml"
    runner.invoke(app, ["briefing-add", "--name", "b1", "--transports", "d1", "--config", str(cfg)])
    assert "d1" in _read_yaml(cfg)["transports"]["use"]


def test_routes_remove(tmp_path):
    cfg = tmp_path / "config.yaml"
    runner.invoke(app, ["routes-add", "--name", "r1", "--transports", "d1", "--include", "rss:", "--config", str(cfg)])
    r = runner.invoke(app, ["routes-remove", "--name", "r1", "--config", str(cfg)])
    assert r.exit_code == 0, r.output
    assert _read_yaml(cfg)["routes"] == []


def test_briefing_remove(tmp_path):
    cfg = tmp_path / "config.yaml"
    runner.invoke(app, ["briefing-add", "--name", "b1", "--transports", "d1", "--config", str(cfg)])
    r = runner.invoke(app, ["briefing-remove", "--name", "b1", "--config", str(cfg)])
    assert r.exit_code == 0, r.output
    assert _read_yaml(cfg)["briefings"] == []


def test_remove_connector_drops_and_deactivates(tmp_path):
    cfg = tmp_path / "config.yaml"
    cx = tmp_path / "connectors.yaml"
    runner.invoke(app, ["add-connector", "--id", "d1", "--type", "discord",
                        "--webhook-url", "https://x/h", "--connectors", str(cx)])
    runner.invoke(app, ["routes-add", "--name", "r1", "--transports", "d1",
                        "--include", "rss:", "--config", str(cfg)])
    assert "d1" in _read_yaml(cfg)["transports"]["use"]

    r = runner.invoke(app, ["remove-connector", "--id", "d1",
                            "--connectors", str(cx), "--config", str(cfg)])
    assert r.exit_code == 0, r.output
    assert _read_yaml(cx)["connectors"] == []
    assert "d1" not in (_read_yaml(cfg).get("transports", {}).get("use") or [])
    assert "still referenced by" in r.output          # route r1 still points at it


# --------------------------------------------------------------------------- #
# doctor config
# --------------------------------------------------------------------------- #
def test_doctor_config_ok(tmp_path):
    cfg = tmp_path / "config.yaml"
    cx = tmp_path / "connectors.yaml"
    _write_yaml(cfg, {"schema_version": 1, "sources": {}, "routes": []})
    _write_yaml(cx, {"connectors": []})

    r = runner.invoke(app, ["doctor", "config", "--config", str(cfg), "--connectors", str(cx)])
    assert r.exit_code == 0, r.output
    assert "Config OK" in r.output
    assert "will be skipped" not in r.output


@pytest.mark.parametrize("api_key", ["${CTI_TEST_MISSING}", ""])
def test_doctor_config_warns_on_pro_feed(tmp_path, monkeypatch, api_key):
    monkeypatch.delenv("CTI_TEST_MISSING", raising=False)
    cfg = tmp_path / "config.yaml"
    cx = tmp_path / "connectors.yaml"
    _write_yaml(cfg, {"schema_version": 1, "sources": {"ransomware_press": {"enabled": True, "api_key": api_key}}, "routes": []})
    _write_yaml(cx, {"connectors": []})

    r = runner.invoke(app, ["doctor", "config", "--config", str(cfg), "--connectors", str(cx)])
    assert r.exit_code == 0, r.output
    assert "Config OK" in r.output
    assert "will be skipped" in r.output
    assert "ransomware_press" in r.output


# --------------------------------------------------------------------------- #
# db-reset
# --------------------------------------------------------------------------- #
def test_db_reset_force_deletes_db_and_wal_shm(tmp_path):
    cfg = tmp_path / "config.yaml"
    _write_yaml(cfg, {"schema_version": 1, "store": {"sqlite_path": "test.db"}})
    db = tmp_path / "test.db"
    wal = tmp_path / "test.db-wal"
    shm = tmp_path / "test.db-shm"
    for p in (db, wal, shm):
        p.write_text("x", encoding="utf-8")

    r = runner.invoke(app, ["db-reset", "--force", "--config", str(cfg)])
    assert r.exit_code == 0, r.output
    assert "Deleted" in r.output
    assert not db.exists()
    assert not wal.exists()
    assert not shm.exists()


def test_db_reset_missing_file(tmp_path):
    cfg = tmp_path / "config.yaml"
    _write_yaml(cfg, {"schema_version": 1, "store": {"sqlite_path": "missing.db"}})
    r = runner.invoke(app, ["db-reset", "--force", "--config", str(cfg)])
    assert r.exit_code == 0, r.output
    assert "not found" in r.output


# --------------------------------------------------------------------------- #
# seen-clear
# --------------------------------------------------------------------------- #
def test_seen_clear_delegates_to_store(tmp_path):
    cfg = tmp_path / "config.yaml"
    _write_yaml(cfg, {"schema_version": 1, "store": {"sqlite_path": "seen.db"}})
    db_path = resolve_db_path("seen.db", str(cfg))
    store = Store(db_path)
    store.upsert_event(make_event_id("rss:Foo", "https://a/1", "t1"), "rss:Foo", "https://a/1", "t1", "s", None)
    store.upsert_event(make_event_id("other:Bar", "https://b/1", "t2"), "other:Bar", "https://b/1", "t2", "s", None)

    r = runner.invoke(app, ["seen-clear", "--source-prefix", "rss:", "--config", str(cfg)])
    assert r.exit_code == 0, r.output
    assert "Seen cleared" in r.output

    conn = sqlite3.connect(db_path)
    try:
        sources = sorted(row[0] for row in conn.execute("SELECT source FROM events").fetchall())
    finally:
        conn.close()
    assert sources == ["other:Bar"]


# --------------------------------------------------------------------------- #
# backfill
# --------------------------------------------------------------------------- #
def test_backfill_nothing_when_empty(tmp_path):
    cfg = tmp_path / "config.yaml"
    _write_yaml(cfg, {"schema_version": 1, "store": {"sqlite_path": "bf.db"}})
    r = runner.invoke(app, ["backfill", "--to", "anything", "--since", "2020-01-01", "--config", str(cfg)])
    assert r.exit_code == 0, r.output
    assert "Nothing to backfill" in r.output


def test_backfill_unknown_transport_errors(tmp_path):
    cfg = tmp_path / "config.yaml"
    _write_yaml(cfg, {"schema_version": 1, "store": {"sqlite_path": "bf.db"}})
    db_path = resolve_db_path("bf.db", str(cfg))
    store = Store(db_path)
    store.upsert_event(make_event_id("rss:F", "https://a/1", "t"), "rss:F", "https://a/1", "t", "s", "2021-01-01T00:00:00Z")

    r = runner.invoke(app, ["backfill", "--to", "nope", "--since", "2020-01-01", "--config", str(cfg)])
    assert r.exit_code != 0


def test_backfill_sends_in_chunks_and_marks_delivery(tmp_path, monkeypatch):
    cfg = tmp_path / "config.yaml"
    cx = tmp_path / "connectors.yaml"
    _write_yaml(cfg, {"schema_version": 1, "store": {"sqlite_path": "bf.db"}, "transports": {"discord": [{"id": "d1", "webhook_url": "http://example/hook"}]}})
    _write_yaml(cx, {"connectors": []})

    db_path = resolve_db_path("bf.db", str(cfg))
    store = Store(db_path)
    total = 23
    for i in range(total):
        src, url, title = "rss:F", "https://a/{}".format(i), "t{}".format(i)
        store.upsert_event(make_event_id(src, url, title), src, url, title, "s", "2021-01-01T00:00:00Z")

    class Recorder:
        def __init__(self):
            self.chunks = []
            self.closed = False

        async def send(self, chunk, title=None, template_text=None):
            self.chunks.append(list(chunk))

        async def aclose(self):
            self.closed = True

    rec = Recorder()
    # backfill does a function-local `from .transports import build_transport`,
    # so the interceptable name lives on the transports module, not on cli.
    monkeypatch.setattr("cassandra_cti.transports.build_transport", lambda ttype, params: rec)

    r = runner.invoke(app, ["backfill", "--to", "d1", "--since", "2020-01-01", "--config", str(cfg), "--connectors", str(cx)])
    assert r.exit_code == 0, r.output
    assert [len(c) for c in rec.chunks] == [10, 10, 3]
    assert sum(len(c) for c in rec.chunks) == total
    assert rec.closed is True
    assert store.unsent_since("d1", "2020-01-01") == []


# --------------------------------------------------------------------------
# channel-add: one command for what used to be four files
# --------------------------------------------------------------------------

def _yaml(p):
    with open(p, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _blank(tmp_path):
    cfg = tmp_path / "config.yaml"
    cx = tmp_path / "connectors.yaml"
    cfg.write_text("schema_version: 1\nsources: {}\nroutes: []\nstore:\n  sqlite_path: \"t.db\"\n")
    cx.write_text("connectors: []\n")
    return cfg, cx


def test_channel_add_wires_connector_route_and_briefing(tmp_path):
    cfg, cx = _blank(tmp_path)
    r = runner.invoke(app, ["channel-add", "--name", "news", "--webhook-url", "https://e/wh",
                            "--batch", "5", "--brief-at", "08:00", "--brief-to", "teams-synthese",
                            "--config", str(cfg), "--connectors", str(cx)])
    assert r.exit_code == 0, r.output

    c = _yaml(cx)["connectors"][0]
    assert c["id"] == "teams-news" and c["type"] == "teams"
    assert c["params"]["webhook_url"] == "https://e/wh"
    assert c["params"]["batching"] == {"enabled": True, "max_items": 5}
    assert c["params"]["throttle_ms"] >= 1000          # the transport raises anything lower

    d = _yaml(cfg)
    route = d["routes"][0]
    assert route["name"] == "news" and route["transports"] == ["teams-news"]
    assert route["include_tags"] == ["news"]
    assert route["template"].endswith("batch_default.j2")   # batching needs a template that iterates
    assert {"teams-news", "teams-synthese"} <= set(d["transports"]["use"])

    b = d["briefings"][0]
    assert b["name"] == "news-daily" and b["transports"] == ["teams-synthese"]
    assert b["at"] == "08:00" and b["include_tags"] == ["news"]


def test_channel_add_can_route_a_source_instead_of_a_tag(tmp_path):
    cfg, cx = _blank(tmp_path)
    r = runner.invoke(app, ["channel-add", "--name", "ransomware", "--webhook-url", "https://e/r",
                            "--source", "ransomware.live", "--template", "templates/ransomware_card.j2",
                            "--config", str(cfg), "--connectors", str(cx)])
    assert r.exit_code == 0, r.output
    route = _yaml(cfg)["routes"][0]
    assert route["include_sources"] == ["ransomware.live"] and "include_tags" not in route
    assert route["template"].endswith("ransomware_card.j2")
    assert "briefings" not in _yaml(cfg)        # no --brief-at, no briefing


def test_channel_add_replaces_a_channel_instead_of_duplicating_it(tmp_path):
    cfg, cx = _blank(tmp_path)
    for couleur in ("D83B01", "107C10"):
        r = runner.invoke(app, ["channel-add", "--name", "news", "--webhook-url", "https://e/wh",
                                "--theme-color", couleur,
                                "--config", str(cfg), "--connectors", str(cx)])
        assert r.exit_code == 0, r.output
    assert len(_yaml(cx)["connectors"]) == 1
    assert _yaml(cx)["connectors"][0]["params"]["theme_color"] == "107C10"
    assert len(_yaml(cfg)["routes"]) == 1


def test_briefing_add_accepts_a_wall_clock_time(tmp_path):
    cfg, _ = _blank(tmp_path)
    r = runner.invoke(app, ["briefing-add", "--name", "matin", "--transports", "teams-x",
                            "--schedule", "24h", "--at", "08:00", "--config", str(cfg)])
    assert r.exit_code == 0, r.output
    assert _yaml(cfg)["briefings"][0]["at"] == "08:00"


def test_channel_add_no_route_builds_a_briefing_only_channel(tmp_path):
    """A briefing channel has no route: routing a tag no feed carries would
    leave a route that can never match."""
    cfg, cx = _blank(tmp_path)
    r = runner.invoke(app, ["channel-add", "--name", "synthese", "--webhook-url", "https://e/s",
                            "--no-route", "--config", str(cfg), "--connectors", str(cx)])
    assert r.exit_code == 0, r.output
    assert "route" not in r.output
    c = _yaml(cfg)
    assert not any(x["name"] == "synthese" for x in (c.get("routes") or []))
    assert "teams-synthese" in c["transports"]["use"]      # active even with no route
    assert any(x["id"] == "teams-synthese" for x in _yaml(cx)["connectors"])


# --------------------------------------------------------------------------
# doctor feeds: broken and quiet are not the same verdict
# --------------------------------------------------------------------------

def _cfg_feeds(tmp_path, feeds):
    cfg = tmp_path / "config.yaml"
    cx = tmp_path / "connectors.yaml"
    rows = "\n".join(f'      - {{ name: "{n}", url: "https://e/{n}", tags: ["{t}"] }}' for n, t in feeds)
    cfg.write_text("schema_version: 1\nsources:\n  rss:\n    enabled: true\n    feeds:\n" + rows + "\nroutes: []\nstore:\n  sqlite_path: \"t.db\"\n")
    cx.write_text("connectors: []\n")
    return cfg, cx


def test_doctor_feeds_separates_broken_from_quiet(tmp_path, monkeypatch):
    """A feed that will not fetch fails the command. A research blog that last
    posted five weeks ago is a note: failing on it would make this useless in CI."""
    from datetime import datetime, timedelta, timezone
    from cassandra_cti.models import Event
    from cassandra_cti.sources.rss import RSS

    now = datetime.now(timezone.utc)
    answers = {
        "fresh": [Event(source="rss:fresh", title="t", url="https://e/1", published_at=now)],
        "quiet": [Event(source="rss:quiet", title="t", url="https://e/2",
                        published_at=now - timedelta(days=200))],
        "dead": RuntimeError("HTTP 404 fetching https://e/dead"),
        "hollow": [],
    }

    async def _fake(self):
        r = answers[self.name]
        if isinstance(r, Exception):
            raise r
        return r

    monkeypatch.setattr(RSS, "fetch", _fake)
    cfg, cx = _cfg_feeds(tmp_path, [("fresh", "news"), ("quiet", "research"),
                                    ("dead", "cert"), ("hollow", "news")])
    r = runner.invoke(app, ["doctor", "feeds", "--config", str(cfg), "--connectors", str(cx)])

    assert r.exit_code == 1                       # dead and hollow are real breakage
    assert "FAIL      dead" in r.output
    assert "EMPTY     hollow" in r.output
    assert "OK        fresh" in r.output
    assert "STALE     quiet" in r.output
    assert "broken: dead, hollow" in r.output
    assert "not an error: quiet" in r.output
    assert "news" in r.output and "research" in r.output   # tags, i.e. which channel


def test_doctor_feeds_passes_when_only_quiet(tmp_path, monkeypatch):
    from datetime import datetime, timedelta, timezone
    from cassandra_cti.models import Event
    from cassandra_cti.sources.rss import RSS

    async def _fake(self):
        return [Event(source="rss:q", title="t", url="https://e/1",
                      published_at=datetime.now(timezone.utc) - timedelta(days=90))]

    monkeypatch.setattr(RSS, "fetch", _fake)
    cfg, cx = _cfg_feeds(tmp_path, [("quiet", "research")])
    r = runner.invoke(app, ["doctor", "feeds", "--config", str(cfg), "--connectors", str(cx)])
    assert r.exit_code == 0
    assert "1/1 feeds reachable and parsing" in r.output

    r2 = runner.invoke(app, ["doctor", "feeds", "--stale-days", "120",
                             "--config", str(cfg), "--connectors", str(cx)])
    assert "STALE" not in r2.output               # --stale-days raises the bar
