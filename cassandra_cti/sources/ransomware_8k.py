# sources/ransomware_8k.py
"""SEC 8-K cyber-incident filings (ransomware.live PRO `/8k`).

US public companies disclosing a cyber incident to the SEC. PRO-only.
Verified shape:
    {"forms": [{company, stockticker, form, file_date, cik, adsh, link,
                item105, item801}]}
Each form has a real SEC/EDGAR `link` (used as the event URL and dedup key) and
a `file_date`. `item105` = "Material Cybersecurity Incident", `item801` = "Other
Events".
"""
from __future__ import annotations
from typing import List

from ..models import Event
from .ransomware_live import _parse_dt
from .rwpro_base import RwProSource

MAX_FORMS = 50


class Ransomware8K(RwProSource):
    source = "ransomware.8k"

    def _path(self) -> str:
        return "/8k"

    def _normalize(self, data) -> List[Event]:
        forms = data.get("forms") if isinstance(data, dict) else data
        forms = sorted(forms or [], key=lambda f: str(f.get("file_date") or ""), reverse=True)
        out: List[Event] = []
        for f in forms[:MAX_FORMS]:
            if not isinstance(f, dict):
                continue
            company = f.get("company") or "Unknown company"
            ticker = f.get("stockticker")
            items = []
            if f.get("item105"):
                items.append("Item 1.05 Material Cybersecurity Incident")
            if f.get("item801"):
                items.append("Item 8.01 Other Events")
            detail = (" - " + "; ".join(items)) if items else ""
            out.append(Event(
                source=self.source,
                title=f"{company} ({ticker})" if ticker else company,
                url=f.get("link"),
                summary=f"SEC {f.get('form', '8-K')} filing{detail}",
                published_at=_parse_dt(f.get("file_date")),
                tags=["sec", "8k", "disclosure"],
                raw=f,
            ))
        return out
