import asyncio
import sqlite3

import cassandra_cti.main as main
from cassandra_cti.models import Event


class FakeSource:
    source = "fake:"

    async def fetch(self):
        return [Event(source="fake:1", title="t1", url="https://e/1", summary="s")]


class FakeTransport:
    def __init__(self):
        self.batch_cfg = {}
        self.sent = 0

    async def send(self, chunk, title=None, template_text=None):
        self.sent += 1

    async def aclose(self):
        pass


def _write_cfg(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "schema_version: 1\n"
        "sources: {}\n"
        "transports:\n"
        "  teams:\n"
        "    - {id: t1, webhook_url: 'http://x'}\n"
        "routes:\n"
        "  - {name: all, include_sources: ['fake:'], transports: ['t1']}\n"
        "store: {sqlite_path: cti.db}\n"
        "metrics: {enabled: false}\n"
    )
    return str(cfg)


def _deliveries_ok(db_path):
    con = sqlite3.connect(db_path)
    try:
        return con.execute(
            "SELECT COUNT(*) FROM deliveries WHERE status='ok'"
        ).fetchone()[0]
    finally:
        con.close()


def _run(cfg, dry, monkeypatch):
    async def fake_sources(_cfg):
        return [FakeSource()]

    monkeypatch.setattr(main, "build_sources", fake_sources)
    monkeypatch.setattr(main, "build_transport", lambda ttype, params: FakeTransport())
    if dry:
        monkeypatch.setenv("CTI_DRY_RUN", "1")
    else:
        monkeypatch.delenv("CTI_DRY_RUN", raising=False)
    asyncio.run(main.run_once(cfg))


def test_dry_run_does_not_persist_deliveries(tmp_path, monkeypatch):
    cfg = _write_cfg(tmp_path)
    _run(cfg, dry=True, monkeypatch=monkeypatch)
    assert _deliveries_ok(str(tmp_path / "cti.db")) == 0


def test_real_run_persists_deliveries(tmp_path, monkeypatch):
    cfg = _write_cfg(tmp_path)
    _run(cfg, dry=False, monkeypatch=monkeypatch)
    assert _deliveries_ok(str(tmp_path / "cti.db")) == 1
