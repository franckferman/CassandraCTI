# sources/redflag.py
from __future__ import annotations
import re
import aiohttp
from bs4 import BeautifulSoup
from datetime import datetime, timezone
from typing import List
from urllib.parse import urljoin
from ..models import Event

_DATE_FILE_RE = re.compile(r'^\d{4}-\d{2}-\d{2}\.txt$')


class RedFlagDomains:
    def __init__(self, base_url: str = "https://dl.red.flag.domains/daily/"):
        self.base_url = base_url
        self.source = "red.flag.domains"

    async def fetch(self) -> List[Event]:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as s:
            async with s.get(self.base_url, headers={"User-Agent": "cassandra-cti/1.0"}, ssl=False) as r:
                if r.status != 200:
                    return []
                html = await r.text()

            # Parse HTML to find .txt links matching YYYY-MM-DD.txt
            try:
                soup = BeautifulSoup(html, "lxml")
            except Exception:
                soup = BeautifulSoup(html, "html.parser")

            links = []
            for a in soup.find_all("a", href=True):
                href = a["href"]
                # Keep only the filename part for matching
                filename = href.rstrip("/").split("/")[-1]
                if _DATE_FILE_RE.match(filename):
                    links.append(href)

            if not links:
                return []

            # Sort by filename to get the latest (YYYY-MM-DD.txt sorts naturally)
            links.sort(key=lambda h: h.rstrip("/").split("/")[-1])
            latest_href = links[-1]
            file_url = urljoin(self.base_url, latest_href)

            async with s.get(file_url, headers={"User-Agent": "cassandra-cti/1.0"}, ssl=False) as r:
                if r.status != 200:
                    return []
                text_content = await r.text()

        # Extract date from filename for title and published_at
        filename = latest_href.rstrip("/").split("/")[-1]
        date_str = filename.replace(".txt", "")
        title = f"Red Flag Domains – {date_str}"

        try:
            published_at = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            published_at = None

        domains = [line.strip() for line in text_content.splitlines() if line.strip() and not line.startswith("#")]
        summary = "\n".join(domains)

        return [Event(
            source=self.source,
            title=title,
            url=file_url,
            summary=summary,
            published_at=published_at,
            tags=["domains"],
            raw={"file": filename, "count": len(domains), "date": date_str},
        )]
