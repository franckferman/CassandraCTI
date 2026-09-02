# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# sources/cisa_kev.py
#
# CISA Known Exploited Vulnerabilities (KEV) catalog. CVEs known to be
# actively exploited in the wild. A single public JSON feed, no API key.
from __future__ import annotations
import json
import socket
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import aiohttp

from ..models import Event
from ..net import ssl_ctx, read_capped

_UA = "cassandra-cti/2.0"
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _parse_date(s: str) -> Optional[datetime]:
    try:
        return datetime.strptime((s or "").strip(), "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


class CisaKev:
    """CISA KEV catalog as a source. Emits one Event per recently-added CVE."""

    def __init__(self, url: str = _KEV_URL, lookback_days: int = 365, max_items: int = 80):
        self.url = url
        self.lookback_days = int(lookback_days)
        self.max_items = int(max_items)
        self.source = "cisa.kev"

    async def _download(self) -> bytes:
        conn = aiohttp.TCPConnector(family=socket.AF_INET, ssl=ssl_ctx())
        async with aiohttp.ClientSession(
            connector=conn, timeout=aiohttp.ClientTimeout(total=30)
        ) as s:
            async with s.get(self.url, headers={"User-Agent": _UA}) as r:
                if r.status != 200:
                    raise RuntimeError(f"HTTP {r.status} fetching {self.url}")
                return await read_capped(r)

    async def fetch(self) -> List[Event]:
        try:
            raw = json.loads((await self._download()).decode("utf-8", "replace"))
        except Exception:
            return []
        vulns = raw.get("vulnerabilities") or []

        cutoff = None
        if self.lookback_days > 0:
            cutoff = datetime.now(timezone.utc) - timedelta(days=self.lookback_days)

        rows = []
        for v in vulns:
            if not isinstance(v, dict):
                continue
            added = _parse_date(v.get("dateAdded", ""))
            if cutoff is not None and added is not None and added < cutoff:
                continue
            rows.append((added, v))

        # Newest first; entries without a parseable date sort last.
        rows.sort(key=lambda t: (t[0] is not None, t[0] or datetime.min.replace(tzinfo=timezone.utc)),
                  reverse=True)
        rows = rows[: self.max_items] if self.max_items > 0 else rows

        events: List[Event] = []
        for added, v in rows:
            cve = (v.get("cveID") or "").strip()
            if not cve:
                continue
            vendor = (v.get("vendorProject") or "").strip()
            product = (v.get("product") or "").strip()
            name = (v.get("vulnerabilityName") or "").strip()
            ransom = str(v.get("knownRansomwareCampaignUse") or "").strip().lower() == "known"
            title = f"{cve}: {name}" if name else cve
            raw_meta = {
                "cve": cve,
                "vendor": vendor,
                "product": product,
                "due_date": (v.get("dueDate") or "").strip(),
                "ransomware_use": ransom,
                "required_action": (v.get("requiredAction") or "").strip(),
                "date_added": (v.get("dateAdded") or "").strip(),
            }
            tags = ["vulnerability", "kev"]
            if ransom:
                tags.append("ransomware")
            events.append(Event(
                source=self.source,
                title=title,
                url=f"https://nvd.nist.gov/vuln/detail/{cve}",
                summary=(v.get("shortDescription") or "").strip(),
                published_at=added,
                tags=tags,
                raw=raw_meta,
            ))
        return events
