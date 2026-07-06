# sources/ransomware_press.py
"""Recent cyber-press news feed (ransomware.live PRO `/press/recent`).

PRO-only (no free equivalent). Verified shape:
    {"results": [{date, victim, domain, country, summary}]}
Items have NO article URL (only the victim `domain`), so events carry no link
and dedup is per (source, victim).
"""
from __future__ import annotations
from typing import List

from ..models import Event
from .ransomware_live import _parse_dt
from .rwpro_base import PRO_BASE, RwProSource


class RansomwarePress(RwProSource):
    source = "ransomware.press"

    def __init__(self, api_key=None, pro_base: str = PRO_BASE, country: str | None = None):
        super().__init__(api_key=api_key, pro_base=pro_base)
        self.country = country

    def _path(self) -> str:
        p = "/press/recent"
        if self.country:
            p += f"?country={self.country}"
        return p

    def _normalize(self, data) -> List[Event]:
        results = data.get("results") if isinstance(data, dict) else data
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
