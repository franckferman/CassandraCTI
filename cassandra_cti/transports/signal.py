# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# transports/signal.py
#
# Signal has no hosted webhook / bot API, so this posts to YOUR self-hosted
# signal-cli-rest-api bridge (e.g. the bbernhard/signal-cli-rest-api container):
#     POST {api_url}/v2/send   {"message", "number", "recipients": [...]}
# `recipients` may mix phone numbers (+336...) and group ids (group.xxxx=) in a
# single connector, so one route can hit a person AND a group at once.
from __future__ import annotations
import asyncio
import os
import socket
from typing import Any, Dict, List, Optional

import aiohttp
from tenacity import (
    retry, stop_after_attempt, wait_exponential, retry_if_not_exception_type,
)
from jinja2 import Template

from ..models import Event
from ..emoji import emoji_for
from ..net import ssl_ctx


class SignalTransport:
    def __init__(self, api_url: str, number: str, recipients,
                 emojis: bool = True, emoji_map: dict | None = None,
                 throttle_ms: int = 0, text_mode: str | None = None,
                 batching: dict | None = None, timeout: int = 30):
        if not api_url:
            raise ValueError("signal: 'api_url' is required (your signal-cli-rest-api endpoint)")
        if not number:
            raise ValueError("signal: 'number' (the registered sender) is required")
        self.api_url = str(api_url).rstrip("/")
        self.number = number
        if isinstance(recipients, str):
            recipients = [r.strip() for r in recipients.split(",")]
        self.recipients = [r for r in (recipients or []) if r]
        if not self.recipients:
            raise ValueError("signal: at least one recipient (number or group id) is required")
        self.emojis = emojis
        self.emoji_map = emoji_map or {}
        self.throttle_ms = throttle_ms
        self.text_mode = text_mode
        self.batch_cfg = batching or {}
        self.timeout = timeout
        self._session: Optional[aiohttp.ClientSession] = None

    async def _ensure_session(self):
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(family=socket.AF_INET, ssl=ssl_ctx())
            self._session = aiohttp.ClientSession(
                connector=connector, timeout=aiohttp.ClientTimeout(total=self.timeout))

    def _render(self, events: List[Event], title: str | None = None,
                template_text: str | None = None) -> str:
        ev0 = events[0]
        ttl = title or ev0.title or "CTI Alert"
        if self.emojis:
            emo = emoji_for(ev0, self.emoji_map)
            if emo and emo not in ttl:
                ttl = f"{emo} {ttl}"
        if template_text:
            body = Template(template_text).render(
                title=ev0.title, events=events, emoji=emoji_for(ev0, self.emoji_map),
                source=ev0.source, summary=ev0.summary, url=ev0.url or '', raw=ev0.raw)
        elif len(events) == 1:
            parts = [ev0.summary or ""]
            if ev0.url:
                parts.append(ev0.url)
            body = "\n\n".join(p for p in parts if p)
        else:
            body = "\n".join(f"• {e.title or ''}" + (f" — {e.url}" if e.url else "")
                             for e in events)
        # Signal messages are plain text (URLs auto-linked); title on the first line.
        return f"{ttl}\n\n{body}".strip()

    @retry(retry=retry_if_not_exception_type(ValueError),
           stop=stop_after_attempt(4),
           wait=wait_exponential(multiplier=1, min=1, max=30), reraise=True)
    async def _post(self, payload: Dict[str, Any]):
        await self._ensure_session()
        try:
            async with self._session.post(f"{self.api_url}/v2/send", json=payload) as resp:
                if resp.status >= 300:
                    text = await resp.text()
                    raise RuntimeError(f"Signal API error {resp.status}: {text[:200]}")
        except aiohttp.InvalidURL:
            # Deterministic bad config: don't retry.
            raise ValueError("signal: invalid api_url (check the connector config)")

    async def send(self, events: List[Event], title: str | None = None,
                   template_text: str | None = None):
        if os.getenv("CTI_DRY_RUN") == "1":
            for ev in events:
                print(f"[DRYRUN:SIGNAL] {ev.source} :: {ev.title} -> {ev.url}")
            return
        text = self._render(events, title=title, template_text=template_text)
        payload: Dict[str, Any] = {"message": text, "number": self.number,
                                   "recipients": self.recipients}
        if self.text_mode:
            payload["text_mode"] = self.text_mode
        await self._post(payload)
        if self.throttle_ms:
            await asyncio.sleep(self.throttle_ms / 1000.0)

    async def aclose(self):
        if self._session and not self._session.closed:
            await self._session.close()
