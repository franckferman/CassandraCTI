# sources/ransomware_press.py
"""Recent cyber-press feed from ransomware.live PRO (`/press/recent`).

PRO-only: there is NO free/v2 or posts.json equivalent, so without a valid
api_key this source degrades gracefully -- it logs a warning and yields nothing
rather than failing the run. Verified response shape:

    {"client","count","filters","results":[{date,victim,domain,country,summary}]}

Note: press items carry no article URL (only the victim `domain`), so events
have no link and dedup is per (source, victim).
"""
from __future__ import annotations
import logging
import socket
from typing import List

import aiohttp

from ..models import Event
from .ransomware_live import _ssl_ctx, _parse_dt

log = logging.getLogger("cassandra-cti.press")

PRO_BASE = "https://api-pro.ransomware.live"
_UA = "cassandra-cti/2.0"


def _clean_key(k) -> str:
    k = (k or "").strip()
    # Treat an unexpanded ${VAR} placeholder (missing env var) as no key.
    if not k or (k.startswith("${") and k.endswith("}")):
        return ""
    return k


class RansomwarePress:
    requires_api_key = True

    def __init__(self, api_key=None, pro_base: str = PRO_BASE, country: str | None = None):
        self.source = "ransomware.press"
        self.api_key = _clean_key(api_key)
        self.pro_base = pro_base.rstrip("/")
        self.country = country

    async def _get_json(self, url: str):
        conn = aiohttp.TCPConnector(family=socket.AF_INET, ssl=_ssl_ctx())
        headers = {"User-Agent": _UA, "Accept": "application/json",
                   "X-API-KEY": self.api_key}
        async with aiohttp.ClientSession(
            connector=conn, timeout=aiohttp.ClientTimeout(total=30)
        ) as s:
            async with s.get(url, headers=headers) as r:
                r.raise_for_status()
                return await r.json(content_type=None)

    def _normalize(self, results) -> List[Event]:
        out: List[Event] = []
        for item in results or []:
            if not isinstance(item, dict):
                continue
            out.append(Event(
                source=self.source,
                title=item.get("victim") or "Cyber press",
                url=None,                       # /press/recent has no article URL
                summary=item.get("summary") or "",
                published_at=_parse_dt(item.get("date")),
                tags=["press", "news"],
                raw=item,
            ))
        return out

    async def fetch(self) -> List[Event]:
        if not self.api_key:
            log.warning("source '%s' requires a PRO api_key -- skipping (no fallback)",
                        self.source)
            return []
        url = f"{self.pro_base}/press/recent"
        if self.country:
            url += f"?country={self.country}"
        try:
            data = await self._get_json(url)
        except Exception as e:
            log.warning("press feed failed: %r", e)
            return []
        results = data.get("results") if isinstance(data, dict) else data
        return self._normalize(results)
