# sources/ransomware_live.py
"""Ransomware victim feed with a resilient multi-backend fallback chain.

Order (first that returns events wins):
  1. API PRO  (https://api-pro.ransomware.live/victims/recent, X-API-KEY)  -- if api_key set
  2. API v2   (https://api.ransomware.live/v2/recentvictims, no auth)
  3. posts.json (https://data.ransomware.live/posts.json)                 -- legacy dump

Every backend is normalised to the same canonical ``raw`` keys so templates
work identically regardless of which one served the data.
"""
from __future__ import annotations
import json
import logging
import re
import socket
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import aiohttp

from ..models import Event
from ..net import ssl_ctx, read_capped
from ..countries import describe as country_describe, flag as country_flag

log = logging.getLogger("cassandra-cti.ransomware")

POSTS_URL = "https://data.ransomware.live/posts.json"
V2_BASE = "https://api.ransomware.live/v2"
PRO_BASE = "https://api-pro.ransomware.live"
_UA = "cassandra-cti/2.0"


def _infostealer_summary(info) -> str:
    """Human summary of ransomware.live's infostealer object, e.g.
    "15 users, 6 employees". Empty when it is missing or all-zero -- the API
    attaches the object even when it correlated nothing, so a bare truthiness
    check would falsely flag victims with no infostealer data."""
    if not isinstance(info, dict):
        return ""
    parts = []
    for key, label in (("users", "users"), ("employees", "employees"),
                       ("thirdparties", "third-parties")):
        n = info.get(key)
        if isinstance(n, int) and n > 0:
            parts.append(f"{n} {label}")
    return ", ".join(parts)


def _infostealer_stealers(info, top: int = 4) -> str:
    """Top infostealer families for a victim, e.g. "Lumma (137), RedLine (132)".
    Read from ransomware.live's infostealer_stats breakdown; "" when absent."""
    if not isinstance(info, dict):
        return ""
    stats = info.get("infostealer_stats")
    if not isinstance(stats, dict):
        return ""
    ranked = sorted(((k, v) for k, v in stats.items() if isinstance(v, int) and v > 0),
                    key=lambda kv: kv[1], reverse=True)
    return ", ".join(f"{name} ({n})" for name, n in ranked[:top])


def _parse_dt(value) -> Optional[datetime]:
    if not value:
        return None
    ds = str(value).strip().replace(" ", "T", 1)
    # Strip fractional seconds while preserving a timezone suffix.
    if "." in ds:
        dot = ds.index(".")
        tail = ds[dot + 1:]
        m = re.search(r"(Z|[+\-]\d{2}:\d{2})$", tail)
        ds = ds[:dot] + (m.group(1) if m else "")
    if ds.endswith("Z"):
        ds = ds[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(ds)
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class RansomwareLive:
    def __init__(self, url: str = POSTS_URL, lookback_days: int = 30,
                 api_key: str | None = None,
                 pro_base: str = PRO_BASE, v2_base: str = V2_BASE):
        self.url = url or POSTS_URL
        self.source = "ransomware.live"
        self.lookback_days = int(lookback_days)
        self.api_key = (api_key or "").strip()
        self.pro_base = pro_base.rstrip("/")
        self.v2_base = v2_base.rstrip("/")

    # -- HTTP -------------------------------------------------------------
    async def _get_json(self, url: str, headers: dict | None = None):
        conn = aiohttp.TCPConnector(family=socket.AF_INET, ssl=ssl_ctx())
        h = {"User-Agent": _UA, "Accept": "application/json"}
        h.update(headers or {})
        async with aiohttp.ClientSession(
            connector=conn, timeout=aiohttp.ClientTimeout(total=30)
        ) as s:
            async with s.get(url, headers=h) as r:
                r.raise_for_status()
                return json.loads(await read_capped(r))

    # -- Normalisation ----------------------------------------------------
    def _normalize(self, r: dict, backend: str) -> Optional[Event]:
        victim = r.get("victim") or re.sub(r"^\*\.", "", r.get("post_title", "")).strip() or "Unknown Victim"
        group = r.get("group") or r.get("group_name") or "Unknown Group"
        leak = r.get("post_url") or r.get("claim_url") or ""
        page = r.get("permalink") or r.get("url") or ""
        discovered = r.get("discovered") or ""
        dt = _parse_dt(discovered) or _parse_dt(r.get("attackdate"))

        if self.lookback_days > 0 and dt is not None:
            if dt < datetime.now(timezone.utc) - timedelta(days=self.lookback_days):
                return None

        country_code = r.get("country") or ""
        canonical = {
            "victim": victim,
            "group_name": group,
            "country": country_code,
            "country_display": country_describe(country_code),
            "country_flag": country_flag(country_code),
            "activity": r.get("activity") or "",
            "website": r.get("website") or r.get("domain") or "",
            "discovered": discovered,
            "attackdate": r.get("attackdate") or "",
            "description": r.get("description") or "",
            "infostealer": r.get("infostealer") or "",
            "infostealer_summary": _infostealer_summary(r.get("infostealer")),
            "infostealer_stealers": _infostealer_stealers(r.get("infostealer")),
            "data_size": r.get("data_size"),
            "press": r.get("press"),
            "leak_url": leak,
            "backend": backend,
        }
        return Event(
            source=self.source,
            title=f"{victim} by {group}",
            # Prefer the stable ransomware.live permalink so dedup identity does
            # not change when the backend falls back pro<->v2 (leak_url kept in raw).
            url=(page or leak or None),
            summary=r.get("description", "") or "",
            published_at=dt,
            tags=["ransomware"],
            raw=canonical,
        )

    def _normalize_all(self, records, backend: str) -> List[Event]:
        out: List[Event] = []
        for r in records or []:
            if not isinstance(r, dict):
                continue
            ev = self._normalize(r, backend)
            if ev is not None:
                out.append(ev)
        return out

    # -- Backends ---------------------------------------------------------
    async def _fetch_pro(self) -> List[Event]:
        data = await self._get_json(f"{self.pro_base}/victims/recent",
                                    headers={"X-API-KEY": self.api_key})
        records = data.get("victims") if isinstance(data, dict) else data
        return self._normalize_all(records, "pro")

    async def _fetch_v2(self) -> List[Event]:
        data = await self._get_json(f"{self.v2_base}/recentvictims")
        records = data.get("victims") if isinstance(data, dict) else data
        return self._normalize_all(records, "v2")

    async def _fetch_posts(self) -> List[Event]:
        data = await self._get_json(self.url)
        return self._normalize_all(data, "posts")

    def _chain(self):
        chain = []
        if self.api_key:
            chain.append(("pro", self._fetch_pro))
        chain.append(("v2", self._fetch_v2))
        chain.append(("posts", self._fetch_posts))
        return chain

    async def fetch(self) -> List[Event]:
        last_err = None
        for name, backend in self._chain():
            try:
                events = await backend()
            except Exception as e:  # noqa: BLE001 - any failure -> next backend
                last_err = e
                log.warning("ransomware backend '%s' failed: %r -- falling back", name, e)
                continue
            if events:
                log.info("ransomware: %d victims via '%s' backend", len(events), name)
                return events
            log.info("ransomware backend '%s' returned no events -- falling back", name)
        if last_err:
            log.error("ransomware: all backends failed (last: %r)", last_err)
        return []
