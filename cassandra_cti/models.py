# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# models.py
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class Event:
    source: str
    title: str
    url: Optional[str] = None
    summary: str = ""
    published_at: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)


# Fields lifted out of Event.raw and exposed to the web dashboard (history +
# live stream) so category tabs can offer real filters. Kept to a small,
# display-safe whitelist rather than dumping the whole raw payload.
_PUBLIC_META_KEYS = (
    # ransomware.live
    "group_name", "victim", "country", "country_display", "country_flag",
    "activity", "website", "leak_url",
    # CISA KEV (vulnerabilities source)
    "cve", "vendor", "product", "due_date", "ransomware_use", "severity",
    # abuse.ch (IOC source)
    "ioc", "ioc_type", "malware", "confidence", "status", "feed",
)


def public_meta(raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Return the display-safe subset of an event's raw payload for the UI."""
    if not raw:
        return {}
    out: Dict[str, Any] = {}
    for k in _PUBLIC_META_KEYS:
        v = raw.get(k)
        if v not in (None, "", [], {}):
            out[k] = v
    return out
