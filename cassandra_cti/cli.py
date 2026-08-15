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

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help=(
        "CassandraCTI — modular Cyber Threat Intelligence aggregator.\n\n"
        "Quick start:\n"
        "  cassandra quickstart            set up config + open the dashboard\n"
        "  cassandra run --web             collect and serve the live dashboard\n\n"
        "Config lives in your OS config dir by default; override with --config / "
        "--connectors on any command."
    ),
)
yaml = YAML()
yaml.indent(mapping=2, sequence=4, offset=2)
# Keep original quoting on round-trip: several feed URLs contain '?', which is
# only valid unquoted in block context — dropping the quotes would emit a config
# that stricter YAML parsers reject (the app's own ruamel loader tolerates it,
# but external tooling should not choke on a file we wrote).
yaml.preserve_quotes = True
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


def _scaffold(cfg_path: Path, cx_path: Path, tpl_dir: Path) -> None:
    """Create config.yaml, connectors.yaml and templates/ if they are missing.

    Shared by `init` and `quickstart`. Copies the shipped examples when present,
    otherwise writes minimal defaults. Existing files are left untouched.
    """
    # cli.py is in cassandra_cti/, so the project root is one level up.
    root = Path(__file__).parent.parent
    src_cfg = root / "config.example.yaml"
    src_cx = root / "connectors.example.yaml"
    src_tpl = root / "templates"

    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cx_path.parent.mkdir(parents=True, exist_ok=True)

    if not cfg_path.exists():
        if src_cfg.exists():
            shutil.copy(src_cfg, cfg_path)
            typer.echo(f"Created {cfg_path} (copied from example)")
        else:
            ysave(cfg_path, {"schema_version": 1, "scheduler": {"mode": "oneshot"},
                             "sources": {}, "transports": {}, "routes": [],
                             "store": {"sqlite_path": ".cassandra_cti.db"}})
            typer.echo(f"Created {cfg_path} (minimal default)")
    else:
        typer.echo(f"Exists: {cfg_path}")

    if not cx_path.exists():
        if src_cx.exists():
            shutil.copy(src_cx, cx_path)
            typer.echo(f"Created {cx_path} (copied from example)")
        else:
            ysave(cx_path, {"connectors": []})
            typer.echo(f"Created {cx_path} (minimal default)")
    else:
        typer.echo(f"Exists: {cx_path}")

    if not tpl_dir.exists():
        if src_tpl.exists() and src_tpl.is_dir():
            shutil.copytree(src_tpl, tpl_dir)
            typer.echo(f"Created {tpl_dir} (copied from templates/)")
        else:
            typer.echo("WARNING: templates/ not found; create it manually.")
    else:
        typer.echo(f"Exists: {tpl_dir}")


@app.command()
def init(config: Path = typer.Option(None, help="Path to config.yaml (default: your config dir)"),
         connectors: Path = typer.Option(None, help="Path to connectors.yaml (default: your config dir)")):
    """Create starter config.yaml, connectors.yaml and templates/ (idempotent)."""
    base = default_dir()
    _scaffold(config or (base / "config.yaml"),
              connectors or (base / "connectors.yaml"),
              base / "templates")


@app.command()
def quickstart(web: bool = typer.Option(True, "--web/--no-web", help="Open the live dashboard after setup"),
               web_host: str = typer.Option("127.0.0.1", "--web-host", help="Dashboard bind address"),
               web_port: int = typer.Option(8080, "--web-port", help="Dashboard port"),
               config: Path = typer.Option(None, help="Path to config.yaml"),
               connectors: Path = typer.Option(None, help="Path to connectors.yaml")):
    """Get running in one command: scaffold config, then open the dashboard.

    Creates the config files if missing, then starts the collector with the web
    dashboard. Use --no-web to only scaffold.

    Examples:
      cassandra quickstart              set up + open http://127.0.0.1:8080
      cassandra quickstart --no-web     just create the config files
    """
    base = default_dir()
    cfg_path = config or (base / "config.yaml")
    cx_path = connectors or (base / "connectors.yaml")
    _scaffold(cfg_path, cx_path, base / "templates")
    typer.echo("")
    typer.echo(f"Config ready: {cfg_path}")
    typer.echo(f"Connectors:   {cx_path}")
    if not web:
        typer.echo("Next: edit the config to enable sources/routes, then run "
                   "`cassandra run` (add --web for the dashboard).")
        return
    typer.echo("Starting the collector with the live dashboard...")
    _do_run(str(cfg_path), str(cx_path), None, loop=True, interval=300,
            web=True, web_host=web_host, web_port=web_port)


@app.command("list")
def list_items(config: Path = typer.Option(None), connectors: Path = typer.Option(None)):
    """Show configured sources (all kinds), routes and connectors."""
    base = default_dir()
    cfg = yload(config or (base / "config.yaml"))
    cx = yload(connectors or (base / "connectors.yaml"))

    sources = cfg.get("sources", {}) or {}
    typer.echo("Sources:")
    if not sources:
        typer.echo("  (none)")
    for name, s in sources.items():
        s = s or {}
        # A source is active only when `enabled` is truthy — mirror build_sources.
        flag = "on " if s.get("enabled") else "off"
        if name == "rss":
            feeds = s.get("feeds", []) or []
            typer.echo(f"  [{flag}] rss ({len(feeds)} feeds)")
            for f in feeds:
                typer.echo(f"         - {f.get('name')} :: {f.get('url')} :: tags={f.get('tags')}")
        else:
            bits = []
            for k in ("lookback_days", "max_items", "feeds", "country"):
                if s.get(k) not in (None, "", []):
                    bits.append(f"{k}={s.get(k)}")
            ak = s.get("api_key")
            if ak:
                # Never print the value: 'env' = ${VAR} placeholder, 'set' = literal.
                bits.append("api_key=" + ("env" if str(ak).startswith("${") else "set"))
            extra = ("  " + ", ".join(bits)) if bits else ""
            typer.echo(f"  [{flag}] {name}{extra}")

    typer.echo("Routes:")
    for r in cfg.get("routes", []):
        typer.echo(f"  - {r.get('name')} -> {r.get('transports')} via src={r.get('include_sources')} tags={r.get('include_tags')} regex={r.get('include_regex')}")

    briefings = cfg.get("briefings", []) or []
    if briefings:
        typer.echo("Briefings:")
        for b in briefings:
            typer.echo(f"  - {b.get('name')} every {b.get('schedule', '24h')} -> {b.get('transports')} "
                       f"src={b.get('include_sources')} tags={b.get('include_tags')}")

    typer.echo("Connectors:")
    for c in cx.get("connectors", []):
        typer.echo(f"  - {c.get('id')} [{c.get('type')}]")


@app.command()
def add_source(kind: str = typer.Argument(..., help="rss|ransomware_live|redflag|kev|abusech"),
               name: str = typer.Option(None, help="Feed name (rss)"),
               url: str = typer.Option(None, help="Feed URL (rss)"),
               tags: Optional[str] = typer.Option(None, help="comma-separated tags (rss)"),
               api_key: Optional[str] = typer.Option(None, help="Auth-Key (abusech, optional)"),
               feeds: Optional[str] = typer.Option(
                   None, help="abuse.ch feeds, comma-separated: feodo,threatfox,urlhaus,malwarebazaar"),
               config: Path = typer.Option(None)):
    """Enable a data source: rss, ransomware.live, red-flag-domains, CISA KEV or abuse.ch."""
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
    elif kind in ("kev", "cisa_kev"):
        s = cfg["sources"].setdefault("cisa_kev", {"enabled": True})
        s["enabled"] = True
    elif kind in ("abusech", "abuse_ch"):
        s = cfg["sources"].setdefault("abusech", {"enabled": True, "feeds": ["feodo", "urlhaus"]})
        s["enabled"] = True
        if feeds:
            s["feeds"] = [f.strip() for f in feeds.split(",") if f.strip()]
        if api_key:
            s["api_key"] = api_key
    else:
        raise typer.BadParameter("Unknown type")

    ysave(cfg_path, cfg)
    typer.echo(f"OK: {kind} added")


@app.command("remove-source")
def remove_source(kind: str = typer.Argument(..., help="rss|ransomware_live|redflag|kev|abusech"),
                  name: Optional[str] = typer.Option(None, help="Feed name to remove (rss)"),
                  url: Optional[str] = typer.Option(None, help="Feed URL to remove (rss)"),
                  config: Path = typer.Option(None)):
    """Remove an RSS feed (by --name or --url), or disable another source."""
    base = default_dir()
    cfg_path = config or (base / "config.yaml")
    cfg = yload(cfg_path)
    sources = cfg.setdefault("sources", {})

    if kind == "rss":
        rss = sources.get("rss") or {}
        feeds = rss.get("feeds") or []
        if not url and not name:
            raise typer.BadParameter("rss removal requires --name or --url")
        before = len(feeds)
        if url:
            feeds = [f for f in feeds if f.get("url") != url]
        else:
            feeds = [f for f in feeds if f.get("name") != name]
        rss["feeds"] = feeds
        sources["rss"] = rss
        removed = before - len(feeds)
        typer.echo(f"Removed {removed} RSS feed(s)" if removed else "No matching feed found")
    else:
        keymap = {"ransomware_live": "ransomware_live", "redflag": "red_flag_domains",
                  "kev": "cisa_kev", "cisa_kev": "cisa_kev",
                  "abusech": "abusech", "abuse_ch": "abusech"}
        key = keymap.get(kind)
        if not key:
            raise typer.BadParameter("Unknown type")
        s = sources.get(key)
        if not s:
            typer.echo(f"{key} not present")
            return
        s["enabled"] = False
        typer.echo(f"{key} disabled (enabled: false)")

    ysave(cfg_path, cfg)


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
def add_connector(id: str = typer.Option(..., "--id", help="Unique connector id"),
                  type: str = typer.Option("teams", "--type", help="teams|discord|telegram|smtp"),
                  webhook_url: Optional[str] = typer.Option(None, help="Incoming webhook URL (teams, discord)"),
                  bot_token: Optional[str] = typer.Option(None, help="Bot token (telegram)"),
                  chat_id: Optional[str] = typer.Option(None, help="Chat id (telegram)"),
                  host: Optional[str] = typer.Option(None, help="SMTP host (smtp)"),
                  port: int = typer.Option(587, help="SMTP port (smtp)"),
                  security: str = typer.Option("starttls", help="SMTP security: starttls|ssl|none (smtp)"),
                  from_addr: Optional[str] = typer.Option(None, help="From address (smtp)"),
                  to_addrs: Optional[str] = typer.Option(None, help="Recipient(s), comma-separated (smtp)"),
                  subject_prefix: str = typer.Option("[CTI]", help="Subject prefix (smtp)"),
                  dashboard_port: int = typer.Option(8080, help="Dashboard port (web)"),
                  token: Optional[str] = typer.Option(None, help="Bearer / ?token= auth (web)"),
                  api_url: Optional[str] = typer.Option(None, help="signal-cli-rest-api endpoint (signal)"),
                  number: Optional[str] = typer.Option(None, help="Registered sender number (signal)"),
                  recipients: Optional[str] = typer.Option(None, help="Comma-separated numbers and/or group ids (signal)"),
                  username: Optional[str] = typer.Option(None, help="Display name (discord)"),
                  theme_color: str = typer.Option("000000", help="Card color (teams)"),
                  emojis: bool = typer.Option(True, help="Prefix titles with emojis"),
                  emoji_map: Optional[str] = typer.Option(None, help="inline JSON or path to a JSON file"),
                  batching: Optional[str] = typer.Option(None, help="JSON ex: '{\"enabled\":true,\"max_items\":5}'"),
                  connectors: Path = typer.Option(None)):
    """Add a connector (teams, discord, telegram, smtp, web or signal)."""
    base = default_dir()
    cx_path = connectors or (base / "connectors.yaml")
    cx = yload(cx_path)
    lst = cx.setdefault("connectors", [])

    if any(c.get("id") == id for c in lst):
        typer.echo("ID already present")
        return

    t = type.lower()
    if t in ("teams", "discord"):
        if not webhook_url:
            raise typer.BadParameter(f"{t} requires --webhook-url")
        params = {"webhook_url": webhook_url, "emojis": emojis}
        if t == "teams":
            params["theme_color"] = theme_color
        if t == "discord" and username:
            params["username"] = username
    elif t == "telegram":
        if not bot_token or not chat_id:
            raise typer.BadParameter("telegram requires --bot-token and --chat-id")
        params = {"bot_token": bot_token, "chat_id": chat_id, "emojis": emojis}
    elif t == "smtp":
        if not host or not from_addr or not to_addrs:
            raise typer.BadParameter("smtp requires --host, --from-addr and --to-addrs")
        params = {"host": host, "port": port, "security": security,
                  "from_addr": from_addr, "to_addrs": to_addrs,
                  "subject_prefix": subject_prefix, "emojis": emojis}
    elif t == "web":
        # Dedicated --dashboard-port avoids colliding with the SMTP --port default.
        params = {"host": host or "127.0.0.1", "port": dashboard_port}
        if token:
            params["token"] = token
    elif t == "signal":
        if not api_url or not number or not recipients:
            raise typer.BadParameter("signal requires --api-url, --number and --recipients")
        params = {"api_url": api_url, "number": number,
                  "recipients": [r.strip() for r in recipients.split(",") if r.strip()],
                  "emojis": emojis}
    else:
        raise typer.BadParameter(f"Unknown connector type: {type}")

    if emoji_map:
        import json as _json
        if os.path.isfile(emoji_map):
            with open(emoji_map, "r", encoding="utf-8") as _fp:
                params["emoji_map"] = _json.load(_fp)
        else:
            params["emoji_map"] = _json.loads(emoji_map)
    if batching:
        import json as _json
        params["batching"] = _json.loads(batching)

    lst.append({"id": id, "type": t, "params": params})
    ysave(cx_path, cx)
    typer.echo(f"Connector {id} ({t}) added")


@app.command()
def routes_add(name: str = typer.Option(...),
               include: Optional[str] = typer.Option(None, help="e.g. 'rss:' or 'ransomware.live'"),
               include_tag: Optional[str] = typer.Option(None, help="single tag"),
               include_regex: Optional[str] = typer.Option(None, help="regex on title/source"),
               include_terms: Optional[str] = typer.Option(None, help="comma-separated entity/company names to watch (title/summary/meta)"),
               transports: str = typer.Option(..., help="comma-separated IDs"),
               template: Optional[Path] = typer.Option(None, help="path to template.j2"),
               config: Path = typer.Option(None)):
    """Add (or replace) a route mapping matched events to transports."""
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
    if include_terms:
        R["include_terms"] = [t.strip() for t in include_terms.split(",") if t.strip()]
    if template:
        R["template"] = str(template)

    routes.append(R)
    cfg["routes"] = routes
    ysave(cfg_path, cfg)
    typer.echo(f"Route {name} added")


@app.command("briefing-add")
def briefing_add(name: str = typer.Option(..., help="Unique briefing name"),
                 transports: str = typer.Option(..., help="comma-separated connector IDs"),
                 include: Optional[str] = typer.Option(None, help="source, e.g. 'cisa.kev' or 'rss:'"),
                 include_tag: Optional[str] = typer.Option(None, help="single tag, e.g. 'cert'"),
                 include_regex: Optional[str] = typer.Option(None, help="regex on title/source"),
                 include_terms: Optional[str] = typer.Option(None, help="comma-separated entity/company names to watch"),
                 schedule: str = typer.Option("24h", help="cadence: 24h | 6h | 30m | 2d"),
                 min_items: int = typer.Option(1, help="skip if fewer than N new items"),
                 max_items: int = typer.Option(40, help="cap items fed to the LLM"),
                 top_n: int = typer.Option(0, "--top-n", help="rank a numbered Top-N (0 = short 2-4 highlight narrative)"),
                 title: Optional[str] = typer.Option(None, help="fixed message title (optional)"),
                 template: Optional[str] = typer.Option(None, help="path to a briefing template"),
                 config: Path = typer.Option(None)):
    """Add (or replace) a periodic LLM briefing in config.yaml."""
    base = default_dir()
    cfg_path = config or (base / "config.yaml")
    cfg = yload(cfg_path)
    briefings = [b for b in cfg.get("briefings", []) or [] if b.get("name") != name]

    B = {"name": name, "transports": transports.split(","), "schedule": schedule,
         "min_items": min_items, "max_items": max_items}
    if top_n:
        B["top_n"] = top_n
    if include:
        B["include_sources"] = [include]
    if include_tag:
        B["include_tags"] = [include_tag]
    if include_regex:
        B["include_regex"] = include_regex
    if include_terms:
        B["include_terms"] = [t.strip() for t in include_terms.split(",") if t.strip()]
    if title:
        B["title"] = title
    if template:
        B["template"] = template

    briefings.append(B)
    cfg["briefings"] = briefings
    ysave(cfg_path, cfg)
    typer.echo(f"Briefing {name} added (every {schedule})")


@app.command("briefing-run")
def briefing_run(name: Optional[str] = typer.Option(None, help="Only this briefing (forces it)"),
                 all: bool = typer.Option(False, "--all", help="Force all briefings now"),
                 dry_run: bool = typer.Option(False, "--dry-run", help="Print [DRYRUN:BRIEFING], call nothing"),
                 config: Path = typer.Option(None), connectors: Path = typer.Option(None)):
    """Send LLM briefings now. No flag = the ones that are due; --name/--all force."""
    base = default_dir()
    cfg = str(config or (base / "config.yaml"))
    cx = str(connectors or (base / "connectors.yaml"))
    if dry_run:
        os.environ["CTI_DRY_RUN"] = "1"

    settings = load_settings(cfg, cx)
    if name:
        settings.briefings = [b for b in settings.briefings if b.name == name]
        if not settings.briefings:
            raise typer.BadParameter(f"No briefing named {name}")
    if not settings.briefings:
        typer.echo("No briefings configured.")
        return

    from .util import resolve_db_path
    from .transports import build_transport
    from .briefings import run_briefings

    store = Store(resolve_db_path(settings.store.get("sqlite_path", ".cassandra_cti.db"), cfg))
    transports_by_id = {}
    for tdef in settings.transports:
        try:
            transports_by_id[tdef.id] = build_transport(tdef.type, tdef.params)
        except Exception as e:
            typer.echo(f"transport {tdef.id}: {e}", err=True)

    force_all = bool(name) or all      # targeting one or --all forces; else due-only
    dry = os.environ.get("CTI_DRY_RUN") == "1"
    import logging
    log = logging.getLogger("cassandra-cti.briefing")

    async def _go():
        n = await run_briefings(settings, store, transports_by_id, dry=dry, log=log,
                                force_all=force_all)
        for tr in transports_by_id.values():
            try:
                await tr.aclose()
            except Exception:
                pass
        return n

    n = asyncio.run(_go())
    typer.echo(f"Briefings sent: {n}")


@app.command()
def doctor(kind: str = typer.Argument(..., help="connector|config"),
           id: Optional[str] = typer.Option(None),
           config: Path = typer.Option(None),
           connectors: Path = typer.Option(None)):
    """Validate the config ('doctor config') or send a live test message
    through a connector ('doctor connector --id <id>')."""
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


def _do_run(cfg: str, cx: str, only, loop: bool, interval: int,
            web: bool, web_host: str, web_port: int,
            dry_run: bool = False, verbose: bool = False,
            since: Optional[str] = None, no_dedupe: bool = False) -> None:
    """Core collect/serve loop, shared by `run` and `quickstart`.

    Kept separate from the Typer command so it can be called with plain Python
    values (calling a Typer command function directly would pass OptionInfo
    objects for any argument left unspecified).
    """
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


@app.command()
def run(config: Path = typer.Option(None), connectors: Path = typer.Option(None),
        loop: bool = typer.Option(False, help="Keep running, re-collecting every --interval seconds"),
        sources: Optional[str] = typer.Option(None, help="Only these sources, e.g. 'rss:' or 'ransomware.live'"),
        dry_run: bool = typer.Option(False, help="Print what would be sent; deliver nothing"),
        verbose: bool = typer.Option(False, help="Debug logging"),
        since: Optional[str] = typer.Option(None, help="ISO8601 or YYYY-MM-DD"),
        no_dedupe: bool = typer.Option(False, help="Re-send events already delivered"),
        interval: int = typer.Option(300, help="Seconds between collections in loop mode"),
        web: bool = typer.Option(False, "--web", help="Serve the live web dashboard (implies --loop)"),
        web_host: str = typer.Option("127.0.0.1", "--web-host", help="Dashboard bind address"),
        web_port: int = typer.Option(8080, "--web-port", help="Dashboard port")):
    """Collect from enabled sources and deliver to routed transports.

    Examples:
      cassandra run                     one collection pass, then exit
      cassandra run --web               collect and serve the dashboard
      cassandra run --dry-run           preview deliveries without sending
      cassandra run --loop --interval 600   re-collect every 10 minutes
    """
    base = default_dir()
    cfg = str(config or (base / "config.yaml"))
    cx = str(connectors or (base / "connectors.yaml"))
    only = sources.split(",") if sources else None
    _do_run(cfg, cx, only, loop=loop, interval=interval, web=web,
            web_host=web_host, web_port=web_port, dry_run=dry_run,
            verbose=verbose, since=since, no_dedupe=no_dedupe)


@app.command("backfill")
def backfill(to: str = typer.Option(..., help="transport id"),
             since: str = typer.Option(..., help="YYYY-MM-DD or ISO"),
             config: Path = typer.Option(None), connectors: Path = typer.Option(None)):
    """Replay stored events not yet delivered to a transport (since a date)."""
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
    """Selectively clear dedup history (by source prefix and/or date)."""
    base = default_dir()
    cfg_path = str(config or (base / "config.yaml"))
    settings = load_settings(cfg_path)
    from .util import resolve_db_path
    store = Store(resolve_db_path(settings.store.get("sqlite_path", ".cassandra_cti.db"), cfg_path))
    store.clear_seen(source_prefix, before, since)
    typer.echo("Seen cleared")


if __name__ == "__main__":
    app()
