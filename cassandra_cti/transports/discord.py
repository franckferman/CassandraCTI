# transports/discord.py
from __future__ import annotations
import asyncio
import os
import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential
from typing import Optional, List, Dict, Any
from jinja2 import Template
from ..models import Event
from ..emoji import emoji_for


class DiscordTransport:
    def __init__(self, webhook_url: str, username: str | None = None, avatar_url: str | None = None,
                 throttle_ms: int = 500, emojis: bool = True, emoji_map: dict | None = None,
                 batching: dict | None = None):
        self.webhook_url = webhook_url
        self.username = username
        self.avatar_url = avatar_url
        self.throttle_ms = throttle_ms
        self.emojis = emojis
        self.emoji_map = emoji_map or {}
        self.batch_cfg = batching or {}
        self._session: Optional[aiohttp.ClientSession] = None

    async def _ensure_session(self):
        if self._session is None or self._session.closed:
            # Force IPv4 to avoid WSL IPv6 issues and increase timeout
            import socket
            connector = aiohttp.TCPConnector(family=socket.AF_INET, ssl=False)
            self._session = aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=60))

    def _render(self, events: List[Event], title: str | None = None, template_text: str | None = None):
        ev0 = events[0]
        ttl = title or ev0.title or "CTI Alert"

        if self.emojis:
            emo = emoji_for(ev0, self.emoji_map)
            if emo and emo not in ttl:
                ttl = f"{emo} {ttl}"

        if template_text:
            tpl = Template(template_text)
            # Render the description/content part
            txt = tpl.render(title=ev0.title, events=events, emoji=emoji_for(ev0, self.emoji_map),
                             source=ev0.source, summary=ev0.summary, url=ev0.url or '', raw=ev0.raw)
        else:
            # Fallback
            if len(events) == 1:
                txt = f"**Source:** {ev0.source}\n\n{ev0.summary}\n\n[View Link]({ev0.url or ''})"
            else:
                lines = [f"- {e.title} - [Lien]({e.url or ''})" for e in events]
                txt = "\n".join(lines)

        return ttl, txt

    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=1, min=1, max=60))
    async def _post(self, payload: dict):
        await self._ensure_session()
        try:
            async with self._session.post(self.webhook_url, json=payload, headers={"Content-Type": "application/json"}) as resp:
                if resp.status >= 300:
                    text = await resp.text()
                    raise RuntimeError(f"Discord webhook error {resp.status}: {text}")
        except aiohttp.InvalidURL:
            raise ValueError(f"Invalid Webhook URL for Discord: {self.webhook_url}")

    async def send(self, events: List[Event], title: str | None = None, template_text: str | None = None):
        if os.getenv("CTI_DRY_RUN") == "1":
            for ev in events:
                print(f"[DRYRUN:DISCORD] {ev.source} :: {ev.title} -> {ev.url}")
            return

        ttl, txt = self._render(events, title=title, template_text=template_text)

        # Build Discord Payload
        # We use an Embed for the main content
        # Enforce Discord Limits: Title 256, Description 4096

        safe_title = ttl[:250] + "..." if len(ttl) > 256 else ttl

        # Truncate description to 4000 to be safe (limit is 4096)
        if len(txt) > 4000:
            txt = txt[:3990] + "\n... (truncated)"

        embed = {
            "title": safe_title,
            "description": txt,
            "color": 5814783,  # Default Discord Blurple-ish
        }

        # Add URL to title if single event
        if len(events) == 1 and events[0].url:
            embed["url"] = events[0].url

        payload: Dict[str, Any] = {
            "embeds": [embed]
        }

        if self.username:
            payload["username"] = self.username
        if self.avatar_url:
            payload["avatar_url"] = self.avatar_url

        await self._post(payload)
        await asyncio.sleep(self.throttle_ms / 1000.0)

    async def aclose(self):
        if self._session:
            await self._session.close()
