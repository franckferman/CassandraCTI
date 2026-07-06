# sources/rwpro_base.py
"""Shared base for ransomware.live PRO-only feeds (auth: X-API-KEY header).

These endpoints have no free/v2/posts.json fallback, so without a valid api_key
the source degrades gracefully: it logs a warning and yields nothing instead of
failing the run (the pipeline isolates each source, so others are unaffected).
"""
from __future__ import annotations
import logging
import socket
from typing import List

import aiohttp

from ..models import Event
from .ransomware_live import _ssl_ctx

PRO_BASE = "https://api-pro.ransomware.live"
_UA = "cassandra-cti/2.0"


def clean_key(k) -> str:
    k = (k or "").strip()
    # An unexpanded ${VAR} placeholder (missing env var) counts as no key.
    if not k or (k.startswith("${") and k.endswith("}")):
        return ""
    return k


class RwProSource:
    """Base PRO-only source. Subclasses set `source` and implement `_path()` +
    `_normalize(data)`."""
    source = "ransomware.pro"

    def __init__(self, api_key=None, pro_base: str = PRO_BASE):
        self.api_key = clean_key(api_key)
        self.pro_base = pro_base.rstrip("/")

    def _path(self) -> str:
        raise NotImplementedError

    def _normalize(self, data) -> List[Event]:
        raise NotImplementedError

    async def _get_json(self, path: str):
        conn = aiohttp.TCPConnector(family=socket.AF_INET, ssl=_ssl_ctx())
        headers = {"User-Agent": _UA, "Accept": "application/json",
                   "X-API-KEY": self.api_key}
        async with aiohttp.ClientSession(
            connector=conn, timeout=aiohttp.ClientTimeout(total=30)
        ) as s:
            async with s.get(self.pro_base + path, headers=headers) as r:
                r.raise_for_status()
                return await r.json(content_type=None)

    async def fetch(self) -> List[Event]:
        log = logging.getLogger("cassandra-cti." + self.source)
        if not self.api_key:
            log.warning("source '%s' requires a PRO api_key -- skipping (no fallback)",
                        self.source)
            return []
        try:
            data = await self._get_json(self._path())
        except Exception as e:
            log.warning("%s feed failed: %r", self.source, e)
            return []
        return self._normalize(data)
