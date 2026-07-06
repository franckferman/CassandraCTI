# transports/telegram.py
from __future__ import annotations
import asyncio
import html
import os
import re
import socket
import aiohttp
from tenacity import (
    retry, stop_after_attempt, wait_exponential, retry_if_not_exception_type,
)
from typing import Optional, List
from jinja2 import Template
from ..models import Event
from ..emoji import emoji_for

TELEGRAM_LIMIT = 4096

# Feeds like CERT-FR ship Markdown with escaped brackets ("\[", "\]"); those
# backslashes render literally under Telegram's HTML parse_mode. Strip the
# Markdown escape backslashes so the text reads cleanly.
_MD_ESCAPE = re.compile(r'\\([\\`*_{}\[\]()#+.!>~=|-])')


def _demarkdown(s):
    return _MD_ESCAPE.sub(r'\1', s or "")


class TelegramParseError(Exception):
    """Raised when Telegram rejects the message because of parse_mode entities.

    Deterministic (retrying won't help) so it is excluded from the retry policy
    and triggers a plain-text resend instead.
    """


class TelegramTransport:
    """Push messages to a Telegram chat/channel via the Bot API.

    Unlike Teams/Discord there is no incoming-webhook URL: sending is a POST to
    ``https://api.telegram.org/bot<token>/sendMessage`` with a ``chat_id``.
    Create the bot with @BotFather, add it to the channel as admin, and use the
    channel @username or numeric id as ``chat_id``.
    """

    def __init__(self, bot_token: str, chat_id, parse_mode: str = "HTML",
                 throttle_ms: int = 1000, emojis: bool = True,
                 emoji_map: dict | None = None, batching: dict | None = None,
                 disable_web_page_preview: bool = True):
        self.api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        self.chat_id = chat_id
        self.parse_mode = parse_mode
        self.throttle_ms = throttle_ms
        self.emojis = emojis
        self.emoji_map = emoji_map or {}
        self.batch_cfg = batching or {}
        self.disable_preview = disable_web_page_preview
        self._session: Optional[aiohttp.ClientSession] = None

    async def _ensure_session(self):
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(family=socket.AF_INET)
            self._session = aiohttp.ClientSession(
                connector=connector, timeout=aiohttp.ClientTimeout(total=30))

    def _render(self, events: List[Event], title: str | None = None,
                template_text: str | None = None) -> str:
        ev0 = events[0]
        ttl = title or ev0.title or "CTI Alert"
        if self.emojis:
            emo = emoji_for(ev0, self.emoji_map)
            if emo and emo not in ttl:
                ttl = f"{emo} {ttl}"

        if template_text:
            # Templates assigned to a Telegram route are expected to emit
            # Telegram-flavoured HTML (see templates/telegram_default.j2).
            body = Template(template_text).render(
                title=ev0.title, events=events,
                emoji=emoji_for(ev0, self.emoji_map),
                source=ev0.source, summary=_demarkdown(ev0.summary),
                url=ev0.url or '', raw=ev0.raw)
        elif len(events) == 1:
            parts = [html.escape(_demarkdown(ev0.summary))]
            if ev0.url:
                safe_url = html.escape(ev0.url, quote=True)
                parts.append(f'<a href="{safe_url}">{html.escape(ev0.url)}</a>')
            body = "\n\n".join(p for p in parts if p)
        else:
            lines = []
            for e in events:
                if e.url:
                    safe_url = html.escape(e.url, quote=True)
                    lines.append(f'• <a href="{safe_url}">{html.escape(e.title or "")}</a>')
                else:
                    lines.append(f"• {html.escape(e.title or '')}")
            body = "\n".join(lines)

        text = f"<b>{html.escape(ttl)}</b>\n\n{body}".strip()
        return text[:TELEGRAM_LIMIT]

    @retry(retry=retry_if_not_exception_type(TelegramParseError),
           stop=stop_after_attempt(5),
           wait=wait_exponential(multiplier=1, min=1, max=60))
    async def _post(self, payload: dict):
        await self._ensure_session()
        async with self._session.post(self.api_url, json=payload) as resp:
            if resp.status == 429:
                body = await resp.json()
                retry_after = int(body.get("parameters", {}).get("retry_after", 5))
                await asyncio.sleep(retry_after)
                raise RuntimeError("Telegram rate limit hit, retrying")
            if resp.status >= 300:
                text = await resp.text()
                if resp.status == 400 and "can't parse entities" in text.lower():
                    raise TelegramParseError(text[:200])
                raise RuntimeError(f"Telegram API error {resp.status}: {text[:200]}")

    async def send(self, events: List[Event], title: str | None = None,
                   template_text: str | None = None):
        if os.getenv("CTI_DRY_RUN") == "1":
            for ev in events:
                print(f"[DRYRUN:TELEGRAM] {ev.source} :: {ev.title} -> {ev.url}")
            return

        text = self._render(events, title=title, template_text=template_text)
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "disable_web_page_preview": self.disable_preview,
        }
        if self.parse_mode:
            payload["parse_mode"] = self.parse_mode

        try:
            await self._post(payload)
        except TelegramParseError:
            # Malformed HTML entities in arbitrary CTI content: resend as plain.
            payload.pop("parse_mode", None)
            await self._post(payload)

        await asyncio.sleep(self.throttle_ms / 1000.0)

    async def aclose(self):
        if self._session:
            await self._session.close()
