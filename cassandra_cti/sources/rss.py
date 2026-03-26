# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# sources/rss.py
from __future__ import annotations
import aiohttp
import feedparser
from typing import List, Dict, Any
from datetime import datetime, timezone
from ..models import Event


class RSS:
    def __init__(self, name: str, url: str, tags: list[str] | None = None):
        self.name = name
        self.url = url
        self.tags = tags or []
        self.source = f"rss:{name}"

    async def fetch(self) -> List[Event]:
        # Using ssl=False to bypass proxy certificate issues
        # Increased timeout to 60s for WSL/slow networks
        # Force IPv4 to avoid WSL IPv6 issues
        import socket
        connector = aiohttp.TCPConnector(family=socket.AF_INET, ssl=False)
        async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=60)) as s:
            # Use standard Browser UA to avoid blocking
            ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            async with s.get(self.url, headers={"User-Agent": ua}) as r:
                data = await r.read()

        feed = feedparser.parse(data)
        out: List[Event] = []

        from bs4 import BeautifulSoup

        def clean_html(html_txt):
            if not html_txt:
                return ""
            soup = BeautifulSoup(html_txt, "html.parser")
            return soup.get_text(separator=" ", strip=True)

        for e in feed.entries:
            title = getattr(e, "title", "(no title)")
            link = getattr(e, "link", None)
            summary = getattr(e, "summary", "")
            if not summary:
                content = getattr(e, "content", [])
                if content:
                    summary = content[0].value
            if not summary:
                summary = getattr(e, "description", "")

            summary = clean_html(summary)

            dt = None
            for attr in ("published_parsed", "updated_parsed"):
                t = getattr(e, attr, None)
                if t:
                    try:
                        dt = datetime(*t[:6], tzinfo=timezone.utc)
                        break
                    except Exception:
                        pass

            out.append(Event(
                source=self.source,
                title=title,
                url=link,
                summary=summary,
                published_at=dt,
                tags=self.tags,
                raw=dict(e)
            ))
        return out


def build_rss_sources(cfg: Dict[str, Any]) -> List[RSS]:
    feeds = cfg.get("feeds", [])
    return [RSS(name=f["name"], url=f["url"], tags=f.get("tags") or []) for f in feeds]
