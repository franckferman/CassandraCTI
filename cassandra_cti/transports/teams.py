# transports/teams.py
from __future__ import annotations
import asyncio
import os
import socket
import aiohttp
from tenacity import retry, stop_after_attempt, wait_fixed
from typing import Optional, List
from html import escape
from jinja2 import Template
from ..models import Event
from ..emoji import emoji_for
from ..util import template_context
from ..net import ssl_ctx, valid_http_url


class TeamsTransport:
    def __init__(self, webhook_url: str, theme_color: str = "000000", throttle_ms: int = 1000,
                 emojis: bool = True, emoji_map: dict | None = None, batching: dict | None = None,
                 quota_warn: int = 50):
        self.webhook_url = webhook_url
        self.theme_color = theme_color
        self.throttle_ms = max(throttle_ms, 1000)
        self.emojis = emojis
        self.emoji_map = emoji_map or {}
        self.batch_cfg = batching or {}
        self.quota_warn = int(quota_warn)
        self._session: Optional[aiohttp.ClientSession] = None

    async def _ensure_session(self):
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(family=socket.AF_INET, ssl=ssl_ctx())
            timeout = aiohttp.ClientTimeout(total=10)
            self._session = aiohttp.ClientSession(connector=connector, timeout=timeout)

    def _render(self, events: List[Event], title: str | None = None, template_text: str | None = None):
        ev0 = events[0]
        ttl = title or ev0.title or "CTI Alert"
        # When the caller imposes the title (the source name), the emoji must
        # describe the source too, not the article. Computed once: the template
        # receives the same emoji as the card heading, or the two disagree on the
        # same card.
        emo = emoji_for(ev0, self.emoji_map, by_source_only=bool(title)) if self.emojis else ""
        if self.emojis:
            if emo and emo not in ttl:
                ttl = f"{emo} {ttl}"

        if template_text:
            # autoescape: the card body is interpreted as HTML by Teams, and feed
            # data is untrusted. Without it a feed title containing <a href=...>
            # renders as a live link inside the channel. Template markup and the
            # Markdown written in the .j2 files are unaffected: only the values
            # substituted into them are escaped.
            tpl = Template(template_text, autoescape=True)
            txt = tpl.render(**template_context(ev0, events, emo))
        else:
            if len(events) == 1:
                txt = (f"**Source:** {escape(ev0.source)}\n\n{escape(ev0.summary or '')}" + (f"\n\n[View Link]({ev0.url})" if valid_http_url(ev0.url) else ""))
            else:
                lines = [f"- {escape(e.title or '')}" + (f" - [Link]({e.url})" if valid_http_url(e.url) else "") for e in events]
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
            # A Workflows webhook answers 202 "accepted", never "posted": the flow
            # can still drop the card afterwards, and the channel stays silent with
            # no trace anywhere. These headers are that trace. The run id is what
            # you search for in the flow's run history; the burst counter is the
            # quota a long catch-up burst can exhaust.
            run = resp.headers.get("x-ms-workflow-run-id")
            if run:
                log.debug("Teams accepted: run %s", run)
            reste = resp.headers.get("x-ms-ratelimit-burst-remaining-workflow-writes")
            try:
                if reste is not None and int(reste) <= self.quota_warn:
                    log.warning("Teams: %s writes left in the Power Automate burst quota "
                                "(run %s). Cards may be accepted and never posted.", reste, run or "?")
            except ValueError:
                pass

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

        if len(events) == 1 and valid_http_url(events[0].url):
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
