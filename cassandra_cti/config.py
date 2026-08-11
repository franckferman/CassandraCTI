# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# config.py
from __future__ import annotations
import os
import yaml
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from .util import expand_env
from .config_schema import SettingsModel


@dataclass
class TransportDef:
    id: str
    type: str
    params: Dict[str, Any]


@dataclass
class RouteDef:
    name: str
    include_sources: Optional[List[str]] = None
    include_tags: Optional[List[str]] = None
    include_regex: Optional[str] = None
    transports: List[str] = None
    template: Optional[str] = None


@dataclass
class BriefingDef:
    name: str
    transports: List[str]
    schedule: str = "24h"
    include_sources: Optional[List[str]] = None
    include_tags: Optional[List[str]] = None
    include_regex: Optional[str] = None
    min_items: int = 1
    max_items: int = 40
    title: Optional[str] = None
    template: Optional[str] = None


@dataclass
class Settings:
    scheduler: Dict[str, Any]
    sources: Dict[str, Any]
    transports: List[TransportDef]
    routes: List[RouteDef]
    store: Dict[str, Any]
    logging: Dict[str, Any]
    metrics: Dict[str, Any]
    filters: Dict[str, Any]
    inventory: Dict[str, Any] = field(default_factory=dict)
    llm: Dict[str, Any] = field(default_factory=dict)
    briefings: List[BriefingDef] = field(default_factory=list)


def _flatten_transports_inline(raw: Dict[str, Any]) -> List[TransportDef]:
    out: List[TransportDef] = []
    tcfg = raw.get("transports", {})
    for ttype, items in tcfg.items():
        if ttype == "use":
            continue
        # items should be a list of dicts
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict) and "id" in item:
                    # copy to avoid mutating original
                    p = item.copy()
                    tid = p.pop("id")
                    # expand env vars in params
                    p = {k: expand_env(v) for k, v in p.items()}
                    out.append(TransportDef(id=tid, type=ttype, params=p))
    return out


def _load_connectors(connectors_path: str | None) -> Dict[str, TransportDef]:
    if not connectors_path:
        return {}
    path = os.path.expanduser(connectors_path)
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    out: Dict[str, TransportDef] = {}
    for c in raw.get("connectors", []):
        if "id" not in c or "type" not in c:
            continue
        params = {k: expand_env(v) for k, v in (c.get("params") or {}).items()}
        out[c["id"]] = TransportDef(id=c["id"], type=c["type"], params=params)
    return out


def load_settings(path: str, connectors_path: str | None = None) -> Settings:
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    # Validate with Pydantic
    SettingsModel(**raw)

    def _walk(x):
        if isinstance(x, dict):
            return {k: _walk(v) for k, v in x.items()}
        if isinstance(x, list):
            return [_walk(v) for v in x]
        if isinstance(x, str):
            return expand_env(x)
        return x

    # Expand env vars
    raw = _walk(raw)

    routes = []
    for r in raw.get("routes", []):
        routes.append(RouteDef(
            name=r.get("name"),
            include_sources=r.get("include_sources"),
            include_tags=r.get("include_tags"),
            include_regex=r.get("include_regex"),
            transports=r.get("transports", []),
            template=r.get("template"),
        ))

    briefings = []
    for b in raw.get("briefings", []) or []:
        briefings.append(BriefingDef(
            name=b.get("name"),
            transports=b.get("transports", []) or [],
            schedule=b.get("schedule", "24h"),
            include_sources=b.get("include_sources"),
            include_tags=b.get("include_tags"),
            include_regex=b.get("include_regex"),
            min_items=int(b.get("min_items", 1)),
            max_items=int(b.get("max_items", 40)),
            title=b.get("title"),
            template=b.get("template"),
        ))

    transports = _flatten_transports_inline(raw)

    use_ids = raw.get("transports", {}).get("use", [])
    if use_ids:
        cx = _load_connectors(connectors_path or os.environ.get("CTI_CONNECTORS", "connectors.yaml"))
        for tid in use_ids:
            if tid in cx:
                transports.append(cx[tid])

    return Settings(
        scheduler=raw.get("scheduler", {}),
        sources=raw.get("sources", {}),
        transports=transports,
        routes=routes,
        store=raw.get("store", {}),
        logging=raw.get("logging", {}),
        metrics=raw.get("metrics", {}),
        filters=raw.get("filters", {}),
        inventory=raw.get("inventory", {}),
        llm=raw.get("llm", {}),
        briefings=briefings,
    )
