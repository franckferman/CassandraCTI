# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# web/app.py
#
# Embedded read-only dashboard. The aiohttp server runs in a dedicated daemon
# thread with its own event loop (see WebDashboardServer), because `run_once`
# is invoked via `asyncio.run()` per scheduler iteration — a server started on
# that loop would be torn down after every cycle. Events cross the thread
# boundary through a `queue.SimpleQueue`; history is read from the SQLite
# store (WAL mode → safe concurrent reads).
from __future__ import annotations
import asyncio
import json
import logging
import queue
import threading
from collections import deque
from typing import Any, Dict, Optional

from aiohttp import web

from ..store import Store
from .page import DASHBOARD_PAGE

log = logging.getLogger("cassandra-cti.web")


class DashboardHub:
    """Fan-out of live events to connected SSE clients.

    `publish` is only ever called from the web server's own event loop (the
    pump task in WebDashboardServer), so the subscriber queues need no locks.
    """

    def __init__(self, max_recent: int = 500):
        self._subscribers: set[asyncio.Queue] = set()
        self.recent: deque[Dict[str, Any]] = deque(maxlen=max_recent)

    def publish(self, item: Dict[str, Any]):
        self.recent.append(item)
        for q in list(self._subscribers):
            try:
                q.put_nowait(item)
            except asyncio.QueueFull:
                # Slow consumer: drop rather than block the pipeline.
                pass

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        self._subscribers.discard(q)


HUB_KEY = web.AppKey("hub", DashboardHub)
TOKEN_KEY = web.AppKey("token", Optional[str])
STORE_KEY = web.AppKey("store", Optional[Store])


def _check_auth(request: web.Request, token: Optional[str]) -> bool:
    if not token:
        return True
    if request.headers.get("Authorization") == f"Bearer {token}":
        return True
    return request.query.get("token") == token


def create_app(db_path: Optional[str], token: Optional[str], hub: DashboardHub) -> web.Application:
    app = web.Application()
    app[HUB_KEY] = hub
    app[TOKEN_KEY] = token
    app[STORE_KEY] = Store(db_path) if db_path else None

    async def index(request: web.Request) -> web.Response:
        if not _check_auth(request, app[TOKEN_KEY]):
            raise web.HTTPUnauthorized(text="missing or invalid token")
        return web.Response(text=DASHBOARD_PAGE, content_type="text/html")

    async def api_events(request: web.Request) -> web.Response:
        if not _check_auth(request, app[TOKEN_KEY]):
            raise web.HTTPUnauthorized(text="missing or invalid token")
        store: Optional[Store] = app[STORE_KEY]
        if store is None:
            return web.json_response({"events": [], "note": "no history database configured"})
        try:
            limit = min(int(request.query.get("limit", 200)), 1000)
        except ValueError:
            limit = 200
        events = store.recent_events(limit=limit,
                                     source=request.query.get("source") or None,
                                     q=request.query.get("q") or None)
        return web.json_response({"events": events})

    async def api_stats(request: web.Request) -> web.Response:
        if not _check_auth(request, app[TOKEN_KEY]):
            raise web.HTTPUnauthorized(text="missing or invalid token")
        store: Optional[Store] = app[STORE_KEY]
        stats = store.stats() if store is not None else {"total": 0, "per_source": {}, "latest": None}
        stats["live_clients"] = len(app[HUB_KEY]._subscribers)
        return web.json_response(stats)

    async def api_stream(request: web.Request) -> web.StreamResponse:
        if not _check_auth(request, app[TOKEN_KEY]):
            raise web.HTTPUnauthorized(text="missing or invalid token")
        resp = web.StreamResponse()
        resp.headers["Content-Type"] = "text/event-stream"
        resp.headers["Cache-Control"] = "no-cache"
        resp.headers["X-Accel-Buffering"] = "no"
        await resp.prepare(request)
        q = app[HUB_KEY].subscribe()
        try:
            await resp.write(b": connected\n\n")
            while True:
                item = await q.get()
                await resp.write(f"data: {json.dumps(item, ensure_ascii=False)}\n\n".encode("utf-8"))
        except (ConnectionResetError, asyncio.CancelledError):
            pass
        finally:
            app[HUB_KEY].unsubscribe(q)
        return resp

    app.router.add_get("/", index)
    app.router.add_get("/api/events", api_events)
    app.router.add_get("/api/stats", api_stats)
    app.router.add_get("/api/stream", api_stream)
    return app


class WebDashboardServer:
    """Runs the dashboard in a daemon thread with its own event loop."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8080,
                 token: Optional[str] = None, db_path: Optional[str] = None):
        self.host = host
        self.port = int(port)
        self.token = token
        self.db_path = db_path
        self.incoming: queue.SimpleQueue = queue.SimpleQueue()
        self.hub = DashboardHub()
        self._thread: Optional[threading.Thread] = None
        self._started = threading.Event()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self):
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name=f"cassandra-web-{self.port}", daemon=True)
        self._thread.start()
        # Give the loop a moment to bind so the CLI can report honestly.
        self._started.wait(timeout=5)

    def _run(self):
        asyncio.run(self._amain())

    async def _amain(self):
        app = create_app(self.db_path, self.token, self.hub)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, self.host, self.port)
            await site.start()
        except Exception as e:
            log.error(f"Web dashboard failed to bind {self.host}:{self.port}: {e}")
            self._started.set()
            return
        log.info(f"Web dashboard listening on http://{self.host}:{self.port}")
        self._started.set()
        # Pump: move events from the thread-safe ingress queue into the hub.
        # Poll instead of `asyncio.to_thread(incoming.get)`: executor threads
        # are non-daemon and would hang the interpreter on shutdown.
        while True:
            try:
                item = self.incoming.get_nowait()
            except queue.Empty:
                await asyncio.sleep(0.2)
                continue
            self.hub.publish(item)


_SERVERS: Dict[tuple, WebDashboardServer] = {}
_SERVERS_LOCK = threading.Lock()


def get_server(host: str, port: int, token: Optional[str] = None,
               db_path: Optional[str] = None) -> WebDashboardServer:
    """One server per (host, port) for the whole process, reused across runs."""
    key = (host, int(port))
    with _SERVERS_LOCK:
        srv = _SERVERS.get(key)
        if srv is None:
            srv = WebDashboardServer(host=host, port=port, token=token, db_path=db_path)
            _SERVERS[key] = srv
        else:
            # Late binding: run_once resolves the DB path after construction.
            if db_path and not srv.db_path:
                srv.db_path = db_path
        return srv
