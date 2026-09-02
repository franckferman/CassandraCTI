# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# sources/abusech.py
#
# abuse.ch malware-infrastructure IOCs. Two feeds:
#   - Feodo Tracker  (botnet C2 IPs)     -- public, NO key required
#   - ThreatFox      (mixed IOCs+family) -- requires a free Auth-Key
# The whole source is optional; without a key only Feodo runs, and if the
# source is disabled nothing is fetched at all.
from __future__ import annotations
import csv
import json
import socket
from datetime import datetime, timezone
from typing import List, Optional

import aiohttp

from ..models import Event
from ..net import ssl_ctx, read_capped

_UA = "cassandra-cti/2.0"
_FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
_THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
_URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"
_MB_URL = "https://mb-api.abuse.ch/api/v1/"


def _parse_dt(s: str) -> Optional[datetime]:
    s = (s or "").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


class AbuseCh:
    """abuse.ch IOC feeds (Feodo public + ThreatFox key-gated)."""

    def __init__(self, api_key: Optional[str] = None, feeds: Optional[List[str]] = None,
                 max_items: int = 60):
        self.api_key = (api_key or "").strip() or None
        self.feeds = [f.lower() for f in (feeds or ["feodo", "threatfox"])]
        self.max_items = int(max_items)
        self.source = "abuse.ch"

    async def _get(self, url: str, *, method: str = "GET", headers=None, data=None) -> bytes:
        conn = aiohttp.TCPConnector(family=socket.AF_INET, ssl=ssl_ctx())
        h = {"User-Agent": _UA}
        h.update(headers or {})
        async with aiohttp.ClientSession(
            connector=conn, timeout=aiohttp.ClientTimeout(total=30)
        ) as s:
            req = s.post(url, headers=h, data=data) if method == "POST" else s.get(url, headers=h)
            async with req as r:
                if r.status != 200:
                    raise RuntimeError(f"HTTP {r.status} fetching {url}")
                return await read_capped(r)

    async def _feodo(self) -> List[Event]:
        try:
            rows = json.loads((await self._get(_FEODO_URL)).decode("utf-8", "replace"))
        except Exception:
            return []
        if not isinstance(rows, list):
            return []

        def _key(r):
            online = str(r.get("status")) == "online"
            when = _parse_dt(r.get("last_online") or "") or _parse_dt(r.get("first_seen") or "")
            return (online, when or datetime.min.replace(tzinfo=timezone.utc))

        rows = [r for r in rows if isinstance(r, dict) and r.get("ip_address")]
        rows.sort(key=_key, reverse=True)
        rows = rows[: self.max_items] if self.max_items > 0 else rows

        out: List[Event] = []
        for r in rows:
            ip = str(r.get("ip_address"))
            port = r.get("port")
            malware = (r.get("malware") or "Unknown").strip()
            country = (r.get("country") or "").strip()
            status = (r.get("status") or "").strip()
            ioc = f"{ip}:{port}" if port else ip
            when = _parse_dt(r.get("last_online") or "") or _parse_dt(r.get("first_seen") or "")
            out.append(Event(
                source=self.source,
                title=f"{malware} C2: {ioc}",
                url=f"https://feodotracker.abuse.ch/browse/host/{ip}/",
                summary=f"{malware} botnet C2 on {ioc} ({country or 'unknown'}, "
                        f"AS{r.get('as_number')} {r.get('as_name') or ''}). Status: {status or 'n/a'}.",
                published_at=when,
                tags=["ioc", "c2", malware.lower()],
                raw={
                    "ioc": ioc, "ioc_type": "ip:port", "malware": malware,
                    "country": country, "status": status, "feed": "feodo",
                },
            ))
        return out

    async def _threatfox(self) -> List[Event]:
        if not self.api_key:
            return []
        body = json.dumps({"query": "get_iocs", "days": 1}).encode("utf-8")
        try:
            data = json.loads((await self._get(
                _THREATFOX_URL, method="POST",
                headers={"Auth-Key": self.api_key, "Content-Type": "application/json"},
                data=body)).decode("utf-8", "replace"))
        except Exception:
            return []
        items = data.get("data") if isinstance(data, dict) else None
        if not isinstance(items, list):
            return []
        items = items[: self.max_items] if self.max_items > 0 else items

        out: List[Event] = []
        for r in items:
            if not isinstance(r, dict):
                continue
            ioc = (r.get("ioc") or "").strip()
            if not ioc:
                continue
            malware = (r.get("malware_printable") or r.get("malware") or "Unknown").strip()
            # Unique per-IOC URL; a shared fallback URL would collapse distinct
            # IOCs to one event id (make_event_id keys off the URL).
            iid = r.get("id")
            ref = (r.get("reference") or "").strip()
            url = ("https://threatfox.abuse.ch/ioc/" + str(iid) + "/") if iid else (ref or None)
            out.append(Event(
                source=self.source,
                title=f"{malware}: {ioc}",
                url=url,
                summary=f"{r.get('threat_type_desc') or r.get('threat_type') or 'IOC'} "
                        f"({malware}), confidence {r.get('confidence_level')}%.",
                published_at=_parse_dt(r.get("first_seen") or ""),
                tags=["ioc", (r.get("ioc_type") or "ioc"), malware.lower()],
                raw={
                    "ioc": ioc, "ioc_type": (r.get("ioc_type") or "").strip(),
                    "malware": malware, "confidence": r.get("confidence_level"),
                    "feed": "threatfox",
                },
            ))
        return out

    async def _urlhaus(self) -> List[Event]:
        # Public CSV dump (newest first), no key required.
        try:
            raw = (await self._get(_URLHAUS_CSV)).decode("utf-8", "replace")
        except Exception:
            return []
        lines = [ln for ln in raw.splitlines() if ln and not ln.startswith("#")]
        out: List[Event] = []
        for row in csv.reader(lines):
            if len(row) < 8:
                continue
            _id, dateadded, url, status, _last, threat, tags_s, link = row[:8]
            if not url:
                continue
            tags = [t for t in (tags_s or "").split(",") if t]
            malware = tags[-1] if tags else (threat or "malware")
            out.append(Event(
                source=self.source,
                title=f"{malware}: {url}",
                url=link or None,  # unique per entry (urlhaus_link) -> distinct id
                summary=f"{threat} · {status}" + ((" · " + ", ".join(tags)) if tags else ""),
                published_at=_parse_dt(dateadded),
                tags=["ioc", "url"] + tags[:3],
                raw={"ioc": url, "ioc_type": "url", "malware": malware,
                     "status": status, "feed": "urlhaus"},
            ))
            if self.max_items and len(out) >= self.max_items:
                break
        return out

    async def _malwarebazaar(self) -> List[Event]:
        if not self.api_key:
            return []
        try:
            data = json.loads((await self._get(
                _MB_URL, method="POST", headers={"Auth-Key": self.api_key},
                data={"query": "recent_detections", "hours": "24"})).decode("utf-8", "replace"))
        except Exception:
            return []
        items = data.get("data") if isinstance(data, dict) else None
        if not isinstance(items, list):
            return []
        items = items[: self.max_items] if self.max_items > 0 else items
        out: List[Event] = []
        for r in items:
            if not isinstance(r, dict):
                continue
            h = (r.get("sha256_hash") or "").strip()
            if not h:
                continue
            malware = (r.get("signature") or "Unknown").strip()
            ftype = (r.get("file_type") or "").strip()
            fname = (r.get("file_name") or "").strip()
            out.append(Event(
                source=self.source,
                title=f"{malware}: {h[:14]}",
                url="https://bazaar.abuse.ch/sample/" + h + "/",  # unique per sample
                summary=(fname + (" · " + ftype if ftype else "")).strip(" ·") or f"{malware} sample",
                published_at=_parse_dt(r.get("first_seen") or ""),
                tags=["ioc", "hash", malware.lower()],
                raw={"ioc": h, "ioc_type": "sha256", "malware": malware, "feed": "malwarebazaar"},
            ))
        return out

    async def fetch(self) -> List[Event]:
        lists: List[List[Event]] = []
        if "feodo" in self.feeds:
            lists.append(await self._feodo())
        if "threatfox" in self.feeds:
            lists.append(await self._threatfox())
        if "urlhaus" in self.feeds:
            lists.append(await self._urlhaus())
        if "malwarebazaar" in self.feeds:
            lists.append(await self._malwarebazaar())
        # Round-robin interleave so that, under a per-source cap downstream, no
        # single feed (e.g. a large ThreatFox pull) starves the others.
        out: List[Event] = []
        i = 0
        while any(i < len(lst) for lst in lists):
            for lst in lists:
                if i < len(lst):
                    out.append(lst[i])
            i += 1
        return out
