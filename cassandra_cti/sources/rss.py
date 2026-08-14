# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# sources/rss.py
from __future__ import annotations
import logging
import re
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List

import aiohttp
import feedparser
from bs4 import BeautifulSoup
from tenacity import retry, stop_after_attempt, wait_exponential

from ..models import Event
from ..net import ssl_ctx, read_capped

log = logging.getLogger("cassandra-cti.rss")

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
MAX_ENTRIES = 200


def clean_html(html_txt) -> str:
    if not html_txt:
        return ""
    return BeautifulSoup(html_txt, "html.parser").get_text(separator=" ", strip=True)


_TERM = ('.', '!', '?', '…', '"', "'", ')', '»', ':')


def tidy_summary(text: str, max_len: int = 1500) -> str:
    """Normalize a feed excerpt for messaging. Feeds often cut the description
    mid-sentence (e.g. it ends on a dangling '"The authentication'); drop that
    short trailing incomplete paragraph, collapse blank runs, and cap the length
    at a word boundary. Appends ' […]' when anything was dropped. Conservative:
    a complete single paragraph (even without a final period) is left untouched."""
    if not text:
        return ""
    t = re.sub(r'[ \t]+', ' ', text).strip()
    t = re.sub(r'\n{3,}', '\n\n', t)
    cut = False
    paras = [p.strip() for p in t.split('\n\n') if p.strip()]
    if len(paras) > 1 and paras[-1] and paras[-1][-1] not in _TERM and len(paras[-1]) < 80:
        paras = paras[:-1]
        cut = True
    t = '\n\n'.join(paras).rstrip()
    if max_len and len(t) > max_len:
        t = t[:max_len].rsplit(' ', 1)[0].rstrip(' ,;:')
        cut = True
    if cut:
        t = t.rstrip() + ' […]'
    return t


class RSS:
    def __init__(self, name: str, url: str, tags: list[str] | None = None):
        self.name = name
        self.url = url
        self.tags = tags or []
        self.source = f"rss:{name}"

    @retry(stop=stop_after_attempt(3),
           wait=wait_exponential(multiplier=1, min=1, max=10),
           reraise=True)
    async def _download(self) -> bytes:
        # Force IPv4 + ssl=False to survive WSL/proxy quirks (project convention).
        connector = aiohttp.TCPConnector(family=socket.AF_INET, ssl=ssl_ctx())
        async with aiohttp.ClientSession(
            connector=connector, timeout=aiohttp.ClientTimeout(total=60)
        ) as s:
            async with s.get(self.url, headers={"User-Agent": _UA}) as r:
                if r.status >= 400:
                    raise RuntimeError(f"HTTP {r.status} fetching {self.url}")
                return await read_capped(r)

    def _entry_to_event(self, e) -> Event:
        title = getattr(e, "title", "(no title)")
        link = getattr(e, "link", None)
        summary = getattr(e, "summary", "")
        if not summary:
            content = getattr(e, "content", [])
            if content:
                summary = content[0].value
        if not summary:
            summary = getattr(e, "description", "")
        summary = tidy_summary(clean_html(summary))

        dt = None
        for attr in ("published_parsed", "updated_parsed"):
            t = getattr(e, attr, None)
            if t:
                try:
                    dt = datetime(*t[:6], tzinfo=timezone.utc)
                    break
                except (TypeError, ValueError):
                    pass

        return Event(source=self.source, title=title, url=link, summary=summary,
                     published_at=dt, tags=self.tags, raw=dict(e))

    async def fetch(self) -> List[Event]:
        # A hard failure (HTTP >=400, network) propagates so the pipeline counts
        # it as a fetch error; other feeds are unaffected (one source per feed).
        data = await self._download()

        feed = feedparser.parse(data)
        if getattr(feed, "bozo", 0) and not feed.entries:
            log.warning("feed %s malformed, no entries: %r",
                        self.source, getattr(feed, "bozo_exception", None))
            return []

        out: List[Event] = []
        for e in feed.entries[:MAX_ENTRIES]:
            try:
                out.append(self._entry_to_event(e))
            except Exception as ex:  # one bad entry must not drop the whole feed
                log.debug("skipping bad entry in %s: %r", self.source, ex)
        return out


def build_rss_sources(cfg: Dict[str, Any]) -> List[RSS]:
    feeds = cfg.get("feeds", [])
    return [RSS(name=f["name"], url=f["url"], tags=f.get("tags") or []) for f in feeds]
