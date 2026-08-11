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

    conns = {c["id"]: c for c in _read_yaml(cx)["connectors"]}
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
