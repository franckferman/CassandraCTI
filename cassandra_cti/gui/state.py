# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# gui/state.py
#
# A read-only snapshot of the workspace, parsed straight from config.yaml and
# connectors.yaml. This is how the app shows what is configured without ever
# importing the core: the files are the contract, the CLI is the only writer.
# Pure stdlib plus PyYAML, no Qt, so it is testable without a display.
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

# Friendly labels for the known source keys. Both the dotted and the
# underscore spellings appear in configs, so map both; an unknown key falls
# back to itself.
SOURCE_LABELS = {
    "rss": "RSS feeds",
    "ransomware.live": "Ransomware.live",
    "ransomware_live": "Ransomware.live",
    "red.flag.domains": "Red Flag Domains",
    "red_flag_domains": "Red Flag Domains",
    "cisa.kev": "CISA KEV",
    "cisa_kev": "CISA KEV",
    "abuse.ch": "abuse.ch",
    "abusech": "abuse.ch",
}


@dataclass(frozen=True)
class SourceItem:
    key: str
    label: str
    enabled: bool
    detail: str = ""
    feed_count: int = 0


@dataclass(frozen=True)
class RouteItem:
    name: str
    transports: tuple = ()
    selector: str = ""


@dataclass(frozen=True)
class BriefingItem:
    name: str
    schedule: str
    transports: tuple = ()
    selector: str = ""


@dataclass(frozen=True)
class ConnectorItem:
    id: str
    type: str


@dataclass(frozen=True)
class LLMSettings:
    enabled: bool = False
    provider: str = "auto"
    model: str = ""
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = ""
    max_tokens: int = 300


@dataclass
class Workspace:
    config_path: Path
    connectors_path: Path
    config_exists: bool
    connectors_exists: bool
    sources: list = field(default_factory=list)
    routes: list = field(default_factory=list)
    briefings: list = field(default_factory=list)
    connectors: list = field(default_factory=list)
    llm: LLMSettings = field(default_factory=LLMSettings)
    scheduler_mode: str = "oneshot"
    max_concurrent_fetches: int = 10
    store_db: str = ""
    error: str = ""

    @property
    def enabled_sources(self) -> int:
        return sum(1 for s in self.sources if s.enabled)


def default_config_dir() -> Path:
    # Mirrors the CLI's default_dir(): the per-user config location. Replicated
    # here (a path, not pipeline logic) so the GUI never imports the core.
    if sys.platform == "win32":
        base = os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))
        return Path(base) / "cassandra-cti"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "cassandra-cti"
    xdg = os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
    return Path(xdg) / "cassandra-cti"


def _safe_load(path: Path) -> dict:
    try:
        if not path.exists():
            return {}
        with path.open("r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError):
        return {}


def _source_detail(key: str, raw: dict) -> tuple:
    # Returns (detail_text, feed_count) for one source entry.
    raw = raw or {}
    if key == "rss":
        feeds = raw.get("feeds") or []
        ua = raw.get("user_agent")
        detail = f"user_agent={ua}" if ua else ""
        return detail, len(feeds)
    bits = []
    for field_name in ("country", "lookback_days", "max_items"):
        value = raw.get(field_name)
        if value not in (None, "", []):
            bits.append(f"{field_name}={value}")
    if raw.get("api_key"):
        key_value = str(raw.get("api_key"))
        bits.append("api_key=" + ("env" if key_value.startswith("${") else "set"))
    return ", ".join(bits), 0


def _selector_text(entry: dict) -> str:
    # A compact description of what an entry matches, for a table cell.
    parts = []
    srcs = entry.get("include_sources")
    tags = entry.get("include_tags")
    terms = entry.get("include_terms")
    regex = entry.get("include_regex")
    if srcs:
        parts.append("src=" + ",".join(str(x) for x in srcs))
    if tags:
        parts.append("tags=" + ",".join(str(x) for x in tags))
    if terms:
        parts.append("terms=" + ",".join(str(x) for x in terms))
    if regex:
        parts.append(f"regex={regex}")
    return " ".join(parts) if parts else "(all events)"


def load_workspace(config_path: Optional[Path] = None,
                   connectors_path: Optional[Path] = None) -> Workspace:
    """Read config.yaml and connectors.yaml into a Workspace snapshot. Missing
    or malformed files are not an error: the matching lists come back empty and
    the *_exists flags say what is on disk."""
    base = default_config_dir()
    cfg_path = Path(config_path) if config_path else base / "config.yaml"
    cx_path = Path(connectors_path) if connectors_path else base / "connectors.yaml"

    cfg = _safe_load(cfg_path)
    cx = _safe_load(cx_path)

    ws = Workspace(
        config_path=cfg_path,
        connectors_path=cx_path,
        config_exists=cfg_path.exists(),
        connectors_exists=cx_path.exists(),
    )

    sources = cfg.get("sources") or {}
    for key, raw in sources.items():
        raw = raw or {}
        detail, feeds = _source_detail(key, raw)
        label = SOURCE_LABELS.get(key, key)
        ws.sources.append(SourceItem(key, label, bool(raw.get("enabled")), detail, feeds))

    for route in cfg.get("routes") or []:
        route = route or {}
        ws.routes.append(RouteItem(
            name=str(route.get("name", "")),
            transports=tuple(route.get("transports") or ()),
            selector=_selector_text(route),
        ))

    for brief in cfg.get("briefings") or []:
        brief = brief or {}
        ws.briefings.append(BriefingItem(
            name=str(brief.get("name", "")),
            schedule=str(brief.get("schedule", "24h")),
            transports=tuple(brief.get("transports") or ()),
            selector=_selector_text(brief),
        ))

    for conn in cx.get("connectors") or []:
        conn = conn or {}
        ws.connectors.append(ConnectorItem(str(conn.get("id", "")), str(conn.get("type", ""))))

    raw_llm = cfg.get("llm") or {}
    ws.llm = LLMSettings(
        enabled=bool(raw_llm.get("enabled")),
        provider=str(raw_llm.get("provider", "auto")),
        model=str(raw_llm.get("model", "")),
        ollama_base_url=str(raw_llm.get("ollama_base_url", "http://localhost:11434")),
        ollama_model=str(raw_llm.get("ollama_model", "")),
        max_tokens=int(raw_llm.get("max_tokens", 300) or 300),
    )

    scheduler = cfg.get("scheduler") or {}
    ws.scheduler_mode = str(scheduler.get("mode", "oneshot"))
    ws.max_concurrent_fetches = int(scheduler.get("max_concurrent_fetches", 10) or 10)
    ws.store_db = str((cfg.get("store") or {}).get("sqlite_path", ""))

    return ws
