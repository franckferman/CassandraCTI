# sources/redflag.py
from __future__ import annotations
import re
import socket
from datetime import datetime, timezone
from typing import List
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

from ..models import Event
from ..net import ssl_ctx, read_capped

_DATE_FILE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\.txt$")
_UA = "cassandra-cti/2.0"


class RedFlagDomains:
    def __init__(self, base_url: str = "https://dl.red.flag.domains/daily/"):
        self.base_url = base_url
        self.source = "red.flag.domains"

    async def _download(self, url: str) -> bytes:
        conn = aiohttp.TCPConnector(family=socket.AF_INET, ssl=ssl_ctx())
        async with aiohttp.ClientSession(
            connector=conn, timeout=aiohttp.ClientTimeout(total=30)
        ) as s:
            async with s.get(url, headers={"User-Agent": _UA}) as r:
                if r.status != 200:
                    raise RuntimeError(f"HTTP {r.status} fetching {url}")
                return await read_capped(r)

    def _pick_latest(self, html: str) -> str | None:
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            soup = BeautifulSoup(html, "html.parser")
        base_host = urlparse(self.base_url).netloc
        links = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            parsed = urlparse(href)
            # Reject absolute / off-host hrefs: an absolute href would let a
            # compromised/MITM'd index pivot the second fetch to an internal
            # address (SSRF) via urljoin. Relative filenames only.
            if parsed.scheme or parsed.netloc:
                continue
            filename = href.rstrip("/").split("/")[-1]
            if _DATE_FILE_RE.match(filename):
                links.append(href)
        if not links:
            return None
        links.sort(key=lambda h: h.rstrip("/").split("/")[-1])
        latest = urljoin(self.base_url, links[-1])
        if urlparse(latest).netloc != base_host:  # belt-and-suspenders
            return None
        return latest

    async def fetch(self) -> List[Event]:
        try:
            index = (await self._download(self.base_url)).decode("utf-8", "replace")
        except Exception:
            return []
        file_url = self._pick_latest(index)
        if not file_url:
            return []
        try:
            content = (await self._download(file_url)).decode("utf-8", "replace")
        except Exception:
            return []

        filename = urlparse(file_url).path.rstrip("/").split("/")[-1]
        date_str = filename.replace(".txt", "")
        title = f"Red Flag Domains – {date_str}"
        try:
            published_at = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            published_at = None

        # Skip comment lines even when indented (check the stripped line).
        domains = [ln.strip() for ln in content.splitlines()
                   if ln.strip() and not ln.strip().startswith("#")]
        return [Event(
            source=self.source,
            title=title,
            url=file_url,
            summary="\n".join(domains),
            published_at=published_at,
            tags=["domains"],
            raw={"file": filename, "count": len(domains), "date": date_str},
        )]
