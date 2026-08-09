# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# transports/web.py
#
# The web dashboard as a connector: route events to it like any other
# transport and they show up live in the browser. The HTTP server itself runs
# in a dedicated thread (see cassandra_cti.web.app) so it survives the
# per-iteration `asyncio.run()` lifecycle of the scheduler loop.
from __future__ import annotations
import os
from typing import List, Optional

from ..models import Event, public_meta
from ..web.app import get_server


def serialize_event(ev: Event) -> dict:
    return {
        "source": ev.source,
        "title": ev.title,
        "url": ev.url,
        "summary": ev.summary or "",
        "published_at": ev.published_at.isoformat() if ev.published_at else None,
        "tags": list(ev.tags or []),
        "meta": public_meta(ev.raw),
    }


class WebTransport:
    def __init__(self, host: str = "127.0.0.1", port: int = 8080,
                 token: Optional[str] = None, db_path: Optional[str] = None,
                 batching: dict | None = None, inventory: dict | None = None,
                 llm: dict | None = None):
        self.host = host
        self.port = int(port)
        self.token = token
        # Late-bound by run_once (DB path, inventory and llm config are resolved
        # from the main settings after transports are built).
        self.db_path = db_path
        self.inventory = inventory or {}
        self.llm = llm or {}
        self.batch_cfg = batching or {}
        self._server = None  # resolved lazily on first send

    def _resolve_server(self):
        if self._server is None:
            self._server = get_server(self.host, self.port, token=self.token,
                                      db_path=self.db_path, inventory=self.inventory,
                                      llm_cfg=self.llm)
        if self.db_path and not self._server.db_path:
            self._server.db_path = self.db_path
        if self.inventory and not self._server.inventory:
            self._server.inventory = self.inventory
        if self.llm and not self._server.llm_cfg:
            self._server.llm_cfg = self.llm
        return self._server

    def ensure_started(self):
        """Bind the dashboard immediately so it is reachable and serves history
        even before any (non-deduplicated) event is routed to it."""
        if os.getenv("CTI_DRY_RUN") == "1":
            return
        self._resolve_server().start()

    async def send(self, events: List[Event], title: str | None = None, template_text: str | None = None):
        if os.getenv("CTI_DRY_RUN") == "1":
            for ev in events:
                print(f"[DRYRUN:WEB] {ev.source} :: {ev.title} -> {ev.url}")
            return

        server = self._resolve_server()
        server.start()
        for ev in events:
            server.incoming.put(serialize_event(ev))

    async def aclose(self):
        # The server is shared process-wide and bound to its own thread;
        # nothing per-run to close here.
        pass
