# transports/smtp.py
from __future__ import annotations
import asyncio
import html
import os
import re
import smtplib
import ssl
from email.message import EmailMessage
from typing import List
from jinja2 import Template
from ..models import Event
from ..emoji import emoji_for

_TAG = re.compile(r"<[^>]+>")


class SMTPTransport:
    """Send CTI alerts by email over SMTP.

    Uses the standard-library ``smtplib`` run in a worker thread
    (``asyncio.to_thread``) so it never blocks the event loop, and adds no new
    dependency. ``security`` selects the connection mode:

      - ``starttls`` (default, port 587)
      - ``ssl``      (implicit TLS, port 465)
      - ``none``     (plaintext, e.g. an internal relay on port 25)
    """

    def __init__(self, host: str, port: int = 587, username: str | None = None,
                 password: str | None = None, from_addr: str | None = None,
                 to_addrs=None, security: str = "starttls",
                 subject_prefix: str = "[CTI]", throttle_ms: int = 1000,
                 emojis: bool = True, emoji_map: dict | None = None,
                 batching: dict | None = None, timeout: int = 30):
        self.host = host
        self.port = int(port)
        self.username = username
        self.password = password
        self.from_addr = from_addr or username or "cassandra-cti@localhost"
        if isinstance(to_addrs, str):
            to_addrs = [a.strip() for a in to_addrs.split(",") if a.strip()]
        self.to_addrs: List[str] = to_addrs or []
        self.security = (security or "starttls").lower()
        self.subject_prefix = subject_prefix
        self.throttle_ms = throttle_ms
        self.emojis = emojis
        self.emoji_map = emoji_map or {}
        self.batch_cfg = batching or {}
        self.timeout = timeout

    def _render(self, events: List[Event], title: str | None = None,
                template_text: str | None = None):
        ev0 = events[0]
        ttl = title or ev0.title or "CTI Alert"
        if self.emojis:
            emo = emoji_for(ev0, self.emoji_map)
            if emo and emo not in ttl:
                ttl = f"{emo} {ttl}"

        if template_text:
            body_html = Template(template_text).render(
                title=ev0.title, events=events,
                emoji=emoji_for(ev0, self.emoji_map),
                source=ev0.source, summary=ev0.summary,
                url=ev0.url or '', raw=ev0.raw)
        elif len(events) == 1:
            link = ""
            if ev0.url:
                safe = html.escape(ev0.url, quote=True)
                link = f'<p><a href="{safe}">{html.escape(ev0.url)}</a></p>'
            body_html = f'<p>{html.escape(ev0.summary or "")}</p>{link}'
        else:
            items = []
            for e in events:
                if e.url:
                    safe = html.escape(e.url, quote=True)
                    items.append(f'<li><a href="{safe}">{html.escape(e.title or "")}</a></li>')
                else:
                    items.append(f'<li>{html.escape(e.title or "")}</li>')
            body_html = f"<ul>{''.join(items)}</ul>"

        subject = f"{self.subject_prefix} {ttl}".strip().replace("\n", " ")
        return subject, body_html

    def _build_message(self, subject: str, body_html: str) -> EmailMessage:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self.from_addr
        msg["To"] = ", ".join(self.to_addrs)
        msg.set_content(_TAG.sub("", body_html).strip() or "(no content)")
        msg.add_alternative(body_html, subtype="html")
        return msg

    def _send_sync(self, msg: EmailMessage) -> None:
        if self.security == "ssl":
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(self.host, self.port,
                                  timeout=self.timeout, context=ctx) as s:
                if self.username:
                    s.login(self.username, self.password)
                s.send_message(msg)
        else:
            with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as s:
                if self.security == "starttls":
                    s.starttls(context=ssl.create_default_context())
                if self.username:
                    s.login(self.username, self.password)
                s.send_message(msg)

    async def send(self, events: List[Event], title: str | None = None,
                   template_text: str | None = None):
        if os.getenv("CTI_DRY_RUN") == "1":
            rcpts = ", ".join(self.to_addrs)
            for ev in events:
                print(f"[DRYRUN:SMTP] {ev.source} :: {ev.title} -> {rcpts}")
            return

        if not self.to_addrs:
            raise ValueError("SMTP transport: no recipient configured (to_addrs)")

        subject, body_html = self._render(events, title=title, template_text=template_text)
        msg = self._build_message(subject, body_html)
        await asyncio.to_thread(self._send_sync, msg)
        await asyncio.sleep(self.throttle_ms / 1000.0)

    async def aclose(self):
        pass
