# sources/ransomware_stats.py
"""Daily tracker digest from ransomware.live PRO `/stats`.

PRO-only. Emits ONE event summarising the tracker. Verified shape:
    {"client", "last_update", "stats": {victims, groups, press}}
Dedup identity includes the day (from last_update) so you get one digest per day.
"""
from __future__ import annotations
from typing import List

from ..models import Event
from .ransomware_live import _parse_dt
from .rwpro_base import RwProSource


class RansomwareStats(RwProSource):
    source = "ransomware.stats"

    def _path(self) -> str:
        return "/stats"

    def _normalize(self, data) -> List[Event]:
        if not isinstance(data, dict):
            return []
        st = data.get("stats") or {}
        last = str(data.get("last_update") or "")
        day = last[:10]  # YYYY-MM-DD -> one digest per day
        summary = (f"Victims tracked: {st.get('victims')} | "
                   f"Groups: {st.get('groups')} | "
                   f"Press articles: {st.get('press')}")
        return [Event(
            source=self.source,
            title=f"Ransomware tracker - {day}" if day else "Ransomware tracker",
            url=None,
            summary=summary,
            published_at=_parse_dt(last),
            tags=["stats", "digest"],
            raw={"stats": st, "last_update": last, "day": day},
        )]
