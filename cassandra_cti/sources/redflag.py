# sources/redflag.py
from __future__ import annotations
import re
import socket
from datetime import datetime, timedelta, timezone
from typing import List
from urllib.parse import urljoin, urlparse

import logging

import aiohttp
from bs4 import BeautifulSoup
from tenacity import retry, stop_after_attempt, wait_exponential

from ..models import Event
from ..net import ssl_ctx, read_capped

_DATE_FILE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\.txt$")
# The same honest agent the feed reader sends: claiming to be a browser is what
# got other sources blocked.
_UA = "CassandraCTI/2.0 (+https://github.com/franckferman/CassandraCTI)"

log = logging.getLogger("cassandra-cti.redflag")


class RedFlagDomains:
    def __init__(self, base_url: str = "https://dl.red.flag.domains/daily/",
                 lookback_days: int = 3):
        self.base_url = base_url
        self.source = "red.flag.domains"
        self.lookback_days = max(1, int(lookback_days))
        # Files already turned into events by this process. The pipeline dedups
        # on the file URL, so a restart cannot double-deliver; this only keeps us
        # from downloading the same lists again on every pass.
        self._seen: set[str] = set()

    # Same reprise as the feed reader: a transient resolver failure must not cost
    # a whole day's list, and this source had no retry at all.
    @retry(stop=stop_after_attempt(3),
           wait=wait_exponential(multiplier=1, min=1, max=10),
           reraise=True)
    async def _download(self, url: str) -> bytes:
        conn = aiohttp.TCPConnector(family=socket.AF_INET, ssl=ssl_ctx())
        async with aiohttp.ClientSession(
            connector=conn, timeout=aiohttp.ClientTimeout(total=30)
        ) as s:
            async with s.get(url, headers={"User-Agent": _UA}) as r:
                if r.status != 200:
                    raise RuntimeError(f"HTTP {r.status} fetching {url}")
                return await read_capped(r)

    def _pick_recent(self, html: str) -> List[str]:
        """Every YYYY-MM-DD.txt in the index, oldest first, within the lookback.

        Taking only the newest file loses a day's list for every day the tool was
        not running, with no way to notice: the next pass finds a newer file and
        the gap is simply never filled.
        """
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            soup = BeautifulSoup(html, "html.parser")
        base_host = urlparse(self.base_url).netloc
        links = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            parsed = urlparse(href)
            # Reject absolutete / off-host hrefs: an absolutete href would let a
            # compromised/MITM'd index pivot the second fetch to an internal
            # address (SSRF) via urljoin. Relative filenames only.
            if parsed.scheme or parsed.netloc:
                continue
            filename = href.rstrip("/").split("/")[-1]
            if _DATE_FILE_RE.match(filename):
                links.append(href)
        if not links:
            return []
        links.sort(key=lambda h: h.rstrip("/").split("/")[-1])
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.lookback_days)).date()
        kept = []
        for href in links[-(self.lookback_days + 1):]:
            name = href.rstrip("/").split("/")[-1]
            try:
                if datetime.strptime(name[:-4], "%Y-%m-%d").date() < cutoff:
                    continue
            except ValueError:
                continue
            absolute = urljoin(self.base_url, href)
            if urlparse(absolute).netloc != base_host:  # belt-and-suspenders
                continue
            kept.append(absolute)
        if not kept:
            # The provider has published nothing for longer than the lookback.
            # Emitting nothing would be a silent behaviour change for anyone who
            # relied on always receiving the most recent list, so fall back to it
            # and say why.
            newest = urljoin(self.base_url, links[-1])
            if urlparse(newest).netloc == base_host:
                log.info("red.flag.domains: nothing within %d days, falling back to %s",
                         self.lookback_days, newest.rsplit("/", 1)[-1])
                return [newest]
        return kept

    async def fetch(self) -> List[Event]:
        # Failing silently would be indistinguishable from "no new list today",
        # which is the normal case: every failure is logged.
        try:
            index = (await self._download(self.base_url)).decode("utf-8", "replace")
        except Exception as e:
            log.warning("red.flag.domains: index %s unreachable: %r", self.base_url, e)
            return []
        urls = self._pick_recent(index)
        if not urls:
            log.warning("red.flag.domains: no YYYY-MM-DD.txt entry in the index at %s", self.base_url)
            return []

        out: List[Event] = []
        for file_url in urls:
            if file_url in self._seen:
                continue
            try:
                content = (await self._download(file_url)).decode("utf-8", "replace")
            except Exception as e:
                log.warning("red.flag.domains: daily list %s unreachable: %r", file_url, e)
                continue
            self._seen.add(file_url)

            filename = urlparse(file_url).path.rstrip("/").split("/")[-1]
            date_str = filename.replace(".txt", "")
            title = f"Red Flag Domains, {date_str}"
            try:
                published_at = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                published_at = None

            # Skip comment lines even when indented (check the stripped line).
            domains = [ln.strip() for ln in content.splitlines()
                       if ln.strip() and not ln.strip().startswith("#")]
            out.append(Event(
                source=self.source,
                title=title,
                url=file_url,
                summary="\n".join(domains),
                published_at=published_at,
                tags=["domains"],
                raw={"file": filename, "count": len(domains), "date": date_str},
            ))
        return out
