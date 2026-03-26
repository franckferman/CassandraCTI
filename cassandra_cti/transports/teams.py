# transports/teams.py
from __future__ import annotations
import asyncio
import os
import socket
import aiohttp
from tenacity import retry, stop_after_attempt, wait_fixed
from typing import Optional, List
from jinja2 import Template
from ..models import Event
from ..emoji import emoji_for


class TeamsTransport:
    def __init__(self, webhook_url: str, theme_color: str = "000000", throttle_ms: int = 1000,
                 emojis: bool = True, emoji_map: dict | None = None, batching: dict | None = None):
        self.webhook_url = webhook_url
        self.theme_color = theme_color
        self.throttle_ms = max(throttle_ms, 1000)
        self.emojis = emojis
        self.emoji_map = emoji_map or {}
        self.batch_cfg = batching or {}
        self._session: Optional[aiohttp.ClientSession] = None

    async def _ensure_session(self):
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(family=socket.AF_INET, ssl=False)
            timeout = aiohttp.ClientTimeout(total=10)
            self._session = aiohttp.ClientSession(connector=connector, timeout=timeout)

    def _render(self, events: List[Event], title: str | None = None, template_text: str | None = None):
        ev0 = events[0]
        ttl = title or ev0.title or "CTI Alert"
        if self.emojis:
            emo = emoji_for(ev0, self.emoji_map)
            if emo and emo not in ttl:
                ttl = f"{emo} {ttl}"

        if template_text:
            tpl = Template(template_text)
            txt = tpl.render(title=ev0.title, events=events, emoji=emoji_for(ev0, self.emoji_map),
                             source=ev0.source, summary=ev0.summary, url=ev0.url or '', raw=ev0.raw)
        else:
            if len(events) == 1:
                txt = f"**Source:** {ev0.source}\n\n{ev0.summary}\n\n[View Link]({ev0.url or ''})"
            else:
                lines = [f"- {e.title} - [Lien]({e.url or ''})" for e in events]
                txt = "\n".join(lines)

        return ttl, txt

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2), reraise=True)
    async def _post(self, payload: dict):
        import logging
        log = logging.getLogger("cassandra-cti.teams")
        await self._ensure_session()
        async with self._session.post(self.webhook_url, json=payload, headers={"Content-Type": "application/json"}) as resp:
            if resp.status == 429:
                retry_after = int(resp.headers.get("Retry-After", 5))
                log.warning(f"Teams rate-limited (429), backing off {retry_after}s")
                await asyncio.sleep(retry_after)
                raise RuntimeError("Teams rate limit hit, retrying")
            if resp.status >= 300:
                text = await resp.text()
                raise RuntimeError(f"Teams webhook error {resp.status}: {text[:200]}")

    async def send(self, events: List[Event], title: str | None = None, template_text: str | None = None):
        if os.getenv("CTI_DRY_RUN") == "1":
            for ev in events:
                print(f"[DRYRUN:TEAMS] {ev.source} :: {ev.title} -> {ev.url}")
            return

        ttl, txt = self._render(events, title=title, template_text=template_text)

        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": self.theme_color,
            "summary": ttl,
            "title": ttl,
            "text": txt,
            "potentialAction": []
        }

        if len(events) == 1 and events[0].url:
            payload["potentialAction"].append({
                "@type": "OpenUri",
                "name": "View Source",
                "targets": [{"os": "default", "uri": events[0].url}]
            })

        await self._post(payload)
        await asyncio.sleep(self.throttle_ms / 1000.0)

    async def aclose(self):
        if self._session:
            await self._session.close()
