# sources/ransomware_live.py
from __future__ import annotations
import re
import aiohttp
from typing import List
from ..models import Event
from datetime import datetime, timedelta, timezone


class RansomwareLive:
    def __init__(self, url: str = "https://data.ransomware.live/posts.json", lookback_days: int = 30):
        self.url = url
        self.source = "ransomware.live"
        self.lookback_days = lookback_days

    async def fetch(self) -> List[Event]:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=25)) as s:
            async with s.get(self.url, headers={"User-Agent": "cassandra-cti/1.0"}, ssl=False) as r:
                r.raise_for_status()
                data = await r.json()

        out: List[Event] = []
        threshold = datetime.now(timezone.utc) - timedelta(days=self.lookback_days)

        for obj in data:
            discovered = obj.get("discovered")
            if not discovered:
                continue

            try:
                ds = discovered.strip().replace(" ", "T", 1)
                # Strip milliseconds while preserving timezone suffix
                if "." in ds:
                    dot_idx = ds.index(".")
                    frac_and_tz = ds[dot_idx + 1:]
                    tz_match = re.search(r'(Z|[+\-]\d{2}:\d{2})$', frac_and_tz)
                    ds = ds[:dot_idx] + (tz_match.group(1) if tz_match else "")
                # Normalise Z suffix
                if ds.endswith("Z"):
                    ds = ds[:-1] + "+00:00"
                dt = datetime.fromisoformat(ds)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError, AttributeError):
                continue

            if dt < threshold:
                continue

            title_raw = obj.get('post_title', 'Unknown Victim')
            group = obj.get('group_name', 'Unknown Group')
            # Remove leading wildcard only (e.g. "*.example.com" -> "example.com")
            victim = re.sub(r'^\*\.', '', title_raw).strip()
            title = f"{victim} by {group}"

            out.append(Event(
                source=self.source,
                title=title,
                url=obj.get("post_url") or obj.get("url") or obj.get("website"),
                summary=obj.get("description", ""),
                published_at=dt,
                tags=["ransomware"],
                raw=obj
            ))
        return out
