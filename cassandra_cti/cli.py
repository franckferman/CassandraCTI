# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# cli.py
from __future__ import annotations
import os
import sys
import asyncio
import csv
import shutil
from pathlib import Path
from typing import Optional
import typer
from ruamel.yaml import YAML
from colorama import init as colorama_init
from .config import load_settings
from .main import run_once
from .store import Store

app = typer.Typer(add_completion=False, help="CassandraCTI CLI")
yaml = YAML()
yaml.indent(mapping=2, sequence=4, offset=2)
colorama_init()


def default_dir() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))
        return Path(base) / "cassandra-cti"
    elif sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "cassandra-cti"
    else:
        return Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))) / "cassandra-cti"


def yload(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return yaml.load(f) or {}


def ysave(path: Path, data: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.dump(data, f)


@app.command()
def init(config: Path = typer.Option(None, help="config.yaml"),
         connectors: Path = typer.Option(None, help="connectors.yaml")):
    base = default_dir()
    cfg_path = config or (base / "config.yaml")
    cx_path = connectors or (base / "connectors.yaml")
    tpl_dir = base / "templates"

    # Determine source paths (assuming running from source or package structure)
    # cli.py is in cassandra_cti/, so project root is one level up
    root = Path(__file__).parent.parent
    src_cfg = root / "config.example.yaml"
    src_cx = root / "connectors.example.yaml"
    src_tpl = root / "templates"

    # Ensure base directory exists
    if not base.exists():
        base.mkdir(parents=True, exist_ok=True)

    if not src_cfg.exists():
        typer.echo(f"WARNING: Source examples not found at {root}. Using internal defaults.")
        # Fallback to internal defaults if files are missing
        pass

    # Config
    if not cfg_path.exists():
        if src_cfg.exists():
            shutil.copy(src_cfg, cfg_path)
            typer.echo(f"Created {cfg_path} (copied from example)")
        else:
            # Fallback minimal config
            sample = {"schema_version": 1, "scheduler": {"mode": "oneshot"}, "sources": {}, "transports": {}, "routes": [], "store": {"sqlite_path": ".cassandra_cti.db"}}
            ysave(cfg_path, sample)
            typer.echo(f"Created {cfg_path} (minimal default)")
    else:
        typer.echo(f"Exists: {cfg_path}")

    # Connectors
    if not cx_path.exists():
        if src_cx.exists():
            shutil.copy(src_cx, cx_path)
            typer.echo(f"Created {cx_path} (copied from example)")
        else:
            sample = {"connectors": []}
            ysave(cx_path, sample)
            typer.echo(f"Created {cx_path} (minimal default)")
    else:
        typer.echo(f"Exists: {cx_path}")

    # Templates
    if not tpl_dir.exists():
        if src_tpl.exists() and src_tpl.is_dir():
            shutil.copytree(src_tpl, tpl_dir)
            typer.echo(f"Created {tpl_dir} (copied from templates/)")
        else:
            typer.echo("WARNING: Source templates directory not found. You may need to create 'templates/' manually.")
    else:
        typer.echo(f"Exists: {tpl_dir}")


@app.command("list")
def list_items(config: Path = typer.Option(None), connectors: Path = typer.Option(None)):
    base = default_dir()
    cfg = yload(config or (base / "config.yaml"))
    cx = yload(connectors or (base / "connectors.yaml"))

    typer.echo("Sources RSS:")
    feeds = cfg.get("sources", {}).get("rss", {}).get("feeds", [])
    for f in feeds:
        typer.echo(f" - {f.get('name')} :: {f.get('url')} :: tags={f.get('tags')}")

    typer.echo("Routes:")
    for r in cfg.get("routes", []):
        typer.echo(f" - {r.get('name')} -> {r.get('transports')} via src={r.get('include_sources')} tags={r.get('include_tags')} regex={r.get('include_regex')}")

    typer.echo("Connectors:")
    for c in cx.get("connectors", []):
        typer.echo(f" - {c.get('id')} [{c.get('type')}]")


@app.command()
def add_source(kind: str = typer.Argument(..., help="rss|ransomware_live|redflag"),
               name: str = typer.Option(None),
               url: str = typer.Option(None),
               tags: Optional[str] = typer.Option(None, help="comma-separated list"),
               config: Path = typer.Option(None)):
    base = default_dir()
    cfg_path = config or (base / "config.yaml")
    cfg = yload(cfg_path)
    cfg.setdefault("sources", {})

    if kind == "rss":
        if not name or not url:
            raise typer.BadParameter("rss requires --name and --url")
        rss = cfg["sources"].setdefault("rss", {"enabled": True, "feeds": []})

        if any(f.get("url") == url for f in rss["feeds"]):
            typer.echo("Already present")
        else:
            rss["feeds"].append({"name": name, "url": url, "tags": (tags.split(',') if tags else [])})
    elif kind == "ransomware_live":
        s = cfg["sources"].setdefault("ransomware_live", {"enabled": True})
        s["enabled"] = True
    elif kind == "redflag":
        s = cfg["sources"].setdefault("red_flag_domains", {"enabled": True})
        s["enabled"] = True
    else:
        raise typer.BadParameter("Unknown type")

    ysave(cfg_path, cfg)
    typer.echo(f"OK: {kind} added")


@app.command("import-feeds")
def import_feeds(file: Path = typer.Argument(..., help="Path to CSV file (Name,URL,Tags)"),
                 config: Path = typer.Option(None)):
    """Import RSS feeds from a CSV file (Name, URL, Tags)"""
    if not file.exists():
        raise typer.BadParameter(f"File not found: {file}")

    base = default_dir()
    cfg_path = config or (base / "config.yaml")
    cfg = yload(cfg_path)
    cfg.setdefault("sources", {})
    rss = cfg["sources"].setdefault("rss", {"enabled": True, "feeds": []})

    count = 0
    with file.open("r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 2:
                continue

            name = row[0].strip()
            url = row[1].strip()
            tags = []
            if len(row) > 2 and row[2].strip():
                tags = [t.strip() for t in row[2].split("|")]

            # Deduplicate by URL
            if any(f.get("url") == url for f in rss["feeds"]):
                typer.echo(f"Skip (already exists): {name}")
                continue

            rss["feeds"].append({"name": name, "url": url, "tags": tags})
            count += 1

    ysave(cfg_path, cfg)
    typer.echo(f"Import finished: {count} feeds added")


@app.command()
def add_connector(id: str = typer.Option(..., "--id"),
                  webhook_url: str = typer.Option(..., help="Teams incoming webhook URL"),
                  theme_color: str = typer.Option("000000"),
                  emojis: bool = typer.Option(True, help="Prefix titles with emojis"),
                  emoji_map: Optional[str] = typer.Option(None, help="inline JSON or path to a JSON file"),
                  batching: Optional[str] = typer.Option(None, help="JSON ex: '{\"enabled\":true,\"max_items\":5}'"),
                  connectors: Path = typer.Option(None)):
    base = default_dir()
    cx_path = connectors or (base / "connectors.yaml")
    cx = yload(cx_path)
    lst = cx.setdefault("connectors", [])

    if any(c.get("id") == id for c in lst):
        typer.echo("ID already present")
        return

    params = {"webhook_url": webhook_url, "theme_color": theme_color, "emojis": emojis}
    if emoji_map:
        import json as _json
        import os as _os
        if _os.path.isfile(emoji_map):
            with open(emoji_map, "r", encoding="utf-8") as _fp:
                params["emoji_map"] = _json.load(_fp)
        else:
            params["emoji_map"] = _json.loads(emoji_map)
    if batching:
        import json as _json
        params["batching"] = _json.loads(batching)

    lst.append({"id": id, "type": "teams", "params": params})
    ysave(cx_path, cx)
    typer.echo(f"Connector {id} added")


@app.command()
def routes_add(name: str = typer.Option(...),
               include: Optional[str] = typer.Option(None, help="e.g. 'rss:' or 'ransomware.live'"),
               include_tag: Optional[str] = typer.Option(None, help="single tag"),
               include_regex: Optional[str] = typer.Option(None, help="regex on title/source"),
               transports: str = typer.Option(..., help="comma-separated IDs"),
               template: Optional[Path] = typer.Option(None, help="path to template.j2"),
               config: Path = typer.Option(None)):
    base = default_dir()
    cfg_path = config or (base / "config.yaml")
    cfg = yload(cfg_path)
    routes = cfg.setdefault("routes", [])

    # Remove existing route with same name if any
    routes = [r for r in routes if r.get("name") != name]

    R = {"name": name, "transports": transports.split(",")}
    if include:
        R["include_sources"] = [include]
    if include_tag:
        R["include_tags"] = [include_tag]
    if include_regex:
        R["include_regex"] = include_regex
    if template:
        R["template"] = str(template)

    routes.append(R)
    cfg["routes"] = routes
    ysave(cfg_path, cfg)
    typer.echo(f"Route {name} added")


@app.command()
def doctor(kind: str = typer.Argument(..., help="connector|config"),
           id: Optional[str] = typer.Option(None),
           config: Path = typer.Option(None),
           connectors: Path = typer.Option(None)):
    base = default_dir()
    if kind == "config":
        try:
            settings = load_settings(str(config or (base / "config.yaml")), str(connectors or (base / "connectors.yaml")))
            typer.echo("Config OK")
            for name in ("ransomware_press", "ransomware_8k", "ransomware_stats"):
                s = settings.sources.get(name) or {}
                k = str(s.get("api_key") or "")
                if s.get("enabled") and (not k or k.startswith("${")):
                    typer.echo(f"WARNING: '{name}' is enabled but has no PRO api_key "
                               "-> it will be skipped (PRO-only feed, no fallback).")
        except Exception as e:
            typer.echo(f"Invalid config: {e}")
    elif kind == "connector":
        if not id:
            raise typer.BadParameter("--id required")

        from .transports import build_transport
        from .models import Event

        cx = yload(connectors or (base / "connectors.yaml"))
        match = next((c for c in cx.get("connectors", []) if c.get("id") == id), None)

        if not match:
            raise typer.BadParameter("Connector not found")

        from .util import expand_env

        def _expand(x):
            if isinstance(x, dict):
                return {k: _expand(v) for k, v in x.items()}
            if isinstance(x, list):
                return [_expand(v) for v in x]
            return expand_env(x) if isinstance(x, str) else x

        t = build_transport(match.get("type"), _expand(match.get("params", {})))

        async def _t():
            try:
                await t.send([Event(source="cli:doctor", title="CTI doctor", url="https://example.com", summary="Test OK")])
                typer.echo("Test message sent successfully")
            except Exception as e:
                typer.echo(f"Error sending message: {e}", err=True)
                raise
            finally:
                if hasattr(t, 'aclose'):
                    await t.aclose()

        try:
            asyncio.run(_t())
        except Exception as e:
            typer.echo(f"Failed: {e}", err=True)
            raise typer.Exit(1)


@app.command()
def run(config: Path = typer.Option(None), connectors: Path = typer.Option(None), loop: bool = typer.Option(False),
        sources: Optional[str] = typer.Option(None, help="e.g. 'rss:' or 'ransomware.live'"),
        dry_run: bool = typer.Option(False),
        verbose: bool = typer.Option(False),
        since: Optional[str] = typer.Option(None, help="ISO8601 or YYYY-MM-DD"),
        no_dedupe: bool = typer.Option(False),
        interval: int = typer.Option(300, help="Interval in seconds for loop mode"),
        web: bool = typer.Option(False, "--web", help="Serve the live web dashboard (implies --loop)"),
        web_host: str = typer.Option("127.0.0.1", "--web-host", help="Dashboard bind address"),
        web_port: int = typer.Option(8080, "--web-port", help="Dashboard port")):

    base = default_dir()
    cfg = str(config or (base / "config.yaml"))
    cx = str(connectors or (base / "connectors.yaml"))
    only = sources.split(",") if sources else None

    if dry_run:
        os.environ["CTI_DRY_RUN"] = "1"
    if verbose:
        os.environ["CTI_LOGLEVEL"] = "DEBUG"
    if since:
        os.environ["CTI_SINCE"] = since
    if no_dedupe:
        os.environ["CTI_NO_DEDUPE"] = "1"

    extra_transports = extra_routes = None
    if web:
        if not loop:
            typer.echo("--web implies --loop: enabling loop mode so the dashboard stays up.")
            loop = True
        from .config import TransportDef, RouteDef
        extra_transports = [TransportDef(id="web-dashboard", type="web",
                                         params={"host": web_host, "port": web_port})]
        # Catch-all route: '.' matches any non-empty source name.
        extra_routes = [RouteDef(name="web-dashboard", include_regex=".",
                                 transports=["web-dashboard"])]
        typer.echo(f"Web dashboard: http://{web_host}:{web_port}")

    async def _once():
        await run_once(cfg, cx, only_sources=only,
                       extra_transports=extra_transports, extra_routes=extra_routes)

    if not loop:
        asyncio.run(_once())
        return

    while True:
        asyncio.run(_once())
        from time import sleep
        sleep(interval)


@app.command("backfill")
def backfill(to: str = typer.Option(..., help="transport id"),
             since: str = typer.Option(..., help="YYYY-MM-DD or ISO"),
             config: Path = typer.Option(None), connectors: Path = typer.Option(None)):

    base = default_dir()
    cfg_path = str(config or (base / "config.yaml"))
    settings = load_settings(cfg_path, str(connectors or (base / "connectors.yaml")))

    from .util import resolve_db_path
    store = Store(resolve_db_path(settings.store.get("sqlite_path", ".cassandra_cti.db"), cfg_path))
    rows = store.unsent_since(to, since)

    if not rows:
        typer.echo("Nothing to backfill")
        return

    tdef = next((t for t in settings.transports if t.id == to), None)
    if not tdef:
        raise typer.BadParameter("Unknown transport")

    from .transports import build_transport
    tr = build_transport(tdef.type, tdef.params)

    from .models import Event
    from .util import make_event_id

    async def _bf():
        # rows: id, source, url, title, summary, published_at
        evs = [Event(source=s, title=ti, url=u, summary=su) for (eid, s, u, ti, su, pub) in rows]

        # Simple chunking
        for i in range(0, len(evs), 10):
            chunk = evs[i:i + 10]
            await tr.send(chunk)
            for ev in chunk:
                store.mark_delivery(make_event_id(ev.source, ev.url, ev.title), to, 'ok')
        await tr.aclose()

    asyncio.run(_bf())
    typer.echo(f"Backfill OK: {len(rows)} events to {to}")


@app.command("db-reset")
def db_reset(config: Path = typer.Option(None), force: bool = typer.Option(False, "--force", "-f", help="Force deletion without confirmation")):
    """Delete the SQLite database file to reset state"""
    base = default_dir()
    cfg_path = str(config or (base / "config.yaml"))
    settings = load_settings(cfg_path)
    from .util import resolve_db_path
    db_path = Path(resolve_db_path(settings.store.get("sqlite_path", ".cassandra_cti.db"), cfg_path))

    if not db_path.exists():
        typer.echo(f"Database file not found at: {db_path}")
        return

    typer.echo(f"Database found at: {db_path}")

    if not force:
        if not typer.confirm("Are you sure you want to delete the database? All history will be lost."):
            typer.echo("Aborted.")
            return

    try:
        db_path.unlink()
        typer.echo(f"Deleted: {db_path}")

        # Cleanup WAL/SHM files if they exist
        wal = db_path.with_suffix(".db-wal")
        shm = db_path.with_suffix(".db-shm")
        if wal.exists():
            wal.unlink()
        if shm.exists():
            shm.unlink()

    except Exception as e:
        typer.echo(f"Error deleting database: {e}", err=True)
        raise typer.Exit(1)


@app.command("seen-clear")
def seen_clear(source_prefix: Optional[str] = typer.Option(None), before: Optional[str] = typer.Option(None),
               since: Optional[str] = typer.Option(None, help="Clear items seen AFTER this date"),
               config: Path = typer.Option(None)):
    base = default_dir()
    cfg_path = str(config or (base / "config.yaml"))
    settings = load_settings(cfg_path)
    from .util import resolve_db_path
    store = Store(resolve_db_path(settings.store.get("sqlite_path", ".cassandra_cti.db"), cfg_path))
    store.clear_seen(source_prefix, before, since)
    typer.echo("Seen cleared")


if __name__ == "__main__":
    app()
