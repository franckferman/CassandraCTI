# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# main.py
from __future__ import annotations
import os
import re
import asyncio
import socket
import aiohttp
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List
from .config import load_settings
from .store import Store
from .sources import build_sources
from .transports import build_transport
from .router import Router
from .models import Event, public_meta
from prometheus_client import Counter, start_http_server

MET_EVENTS = Counter('cassandra_cti_events_sent', 'Events sent', ['route'])
MET_FETCH = Counter('cassandra_cti_fetch_total', 'Fetch by source', ['source', 'status'])


# Failures that mean "the network is having a moment", logged as one line each.
# Anything else keeps its traceback, because anything else is a defect.
_NETWORK = (
    aiohttp.ClientConnectorError,     # covers ClientConnectorDNSError
    aiohttp.ClientConnectorCertificateError,
    aiohttp.ServerTimeoutError,
    aiohttp.ClientPayloadError,
    asyncio.TimeoutError,
    socket.gaierror,
    ConnectionResetError,
)


def _template_uses_events(tpl_text: str) -> bool:
    """True when the template reads the `events` variable, so a batch renders whole."""
    try:
        from jinja2 import Environment, meta
        # autoescape=True is irrelevant here (we only parse to detect variables,
        # never render), but it keeps the Bandit B701 scan clean.
        env = Environment(autoescape=True)
        return "events" in meta.find_undeclared_variables(env.parse(tpl_text))
    except Exception:
        return False  # unparsable template: stay on the safe side, one event per card


def _parse_since():
    s = os.environ.get("CTI_SINCE")
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _tz_aware(dt: datetime) -> datetime:
    """Return dt as UTC-aware if it is naive."""
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


async def run_once(settings_path: str, connectors_path: str | None = None, only_sources: list[str] | None = None,
                   extra_transports: list | None = None, extra_routes: list | None = None):
    settings = load_settings(settings_path, connectors_path)

    lvl = os.environ.get("CTI_LOGLEVEL") or settings.logging.get("level", "INFO")
    logging.basicConfig(level=getattr(logging, lvl))
    log = logging.getLogger("cassandra-cti")

    dry = os.environ.get("CTI_DRY_RUN") == "1"

    if settings.metrics.get('enabled') and not os.environ.get('CTI_METRICS_STARTED'):
        try:
            start_http_server(port=settings.metrics.get('port', 9108), addr=settings.metrics.get('host', '127.0.0.1'))
            os.environ['CTI_METRICS_STARTED'] = '1'
        except Exception as e:
            log.warning(f"Metrics server error: {e}")

    # Resolve DB path (relative paths anchored to the config file's directory)
    from .util import resolve_db_path
    db_path = resolve_db_path(settings.store.get("sqlite_path", ".cassandra_cti.db"), settings_path)
    store = Store(db_path)

    ttl = int(settings.store.get("seen_ttl_days", 0) or 0)
    if ttl > 0:
        store.purge_ttl(ttl)

    transports_by_id: Dict[str, Any] = {}
    for tdef in list(settings.transports) + list(extra_transports or []):
        try:
            tr = build_transport(tdef.type, tdef.params)
            # Give the web dashboard access to the history database and the
            # optional inventory / LLM configuration.
            if tdef.type == "web":
                if getattr(tr, "db_path", None) is None:
                    tr.db_path = db_path
                if not getattr(tr, "inventory", None):
                    tr.inventory = settings.inventory
                if not getattr(tr, "llm", None):
                    tr.llm = settings.llm
                # Bind now so the dashboard is reachable immediately (and serves
                # history) rather than only after the first non-deduped event.
                if hasattr(tr, "ensure_started"):
                    tr.ensure_started()
            transports_by_id[tdef.id] = tr
        except Exception as e:
            log.error(f"Failed to build transport {tdef.id}: {e}")

    router = Router(list(settings.routes) + list(extra_routes or []), transports_by_id)

    sources = await build_sources({"sources": settings.sources})
    if only_sources:
        src_set = set(only_sources)
        sources = [s for s in sources if any(
            getattr(s, "source", "").startswith(tag) or getattr(s, "source", "") == tag for tag in src_set
        )]

    # Every source used to be fetched at once. With the shipped catalogue that is
    # over forty simultaneous DNS lookups and TLS handshakes, and a resolver that
    # blinks answers EAI_AGAIN: the soak run lost Dark Reading, the LLM endpoint
    # and the domain list that way, each looking like an unrelated outage.
    bound = int((getattr(settings, "scheduler", {}) or {}).get("max_concurrent_fetches", 10))
    gate = asyncio.Semaphore(max(1, bound))

    async def _fetch(s):
        try:
            async with gate:
                evs = await s.fetch()
            for _ in evs:
                MET_FETCH.labels(source=getattr(s, 'source', 'unknown'), status='ok').inc()
            return evs
        except _NETWORK as e:
            # A network blip is expected operation, not a bug to dump a stack for.
            # Twelve full tracebacks for one dropped wifi link buries whatever
            # else the log had to say, and reads like a crash when it is not.
            log.error("Source error %s: %s", getattr(s, "source", s), e)
            MET_FETCH.labels(source=getattr(s, 'source', 'unknown'), status='err').inc()
            return []
        except Exception as e:
            log.error(f"Source error {getattr(s, 'source', s)}: {e}", exc_info=True)
            MET_FETCH.labels(source=getattr(s, 'source', 'unknown'), status='err').inc()
            return []

    tasks = [asyncio.create_task(_fetch(s)) for s in sources]
    all_events: List[Event] = []
    for t in tasks:
        all_events.extend(await t)

    # Date filter
    since_dt = _parse_since()
    if since_dt is not None:
        def _after_since(e: Event) -> bool:
            if e.published_at is None:
                return True
            pub = _tz_aware(e.published_at)
            return pub >= since_dt
        all_events = [e for e in all_events if _after_since(e)]

    # Title filters (deny/allow lists + per-source cap)
    flt = settings.filters

    def _compile_filters(patterns):
        out = []
        for p in patterns or []:
            if not p:
                continue
            try:
                out.append(re.compile(p, re.IGNORECASE))
            except re.error as e:
                log.error("invalid title filter regex %r: %s -- ignored", p, e)
        return out

    deny_pats = _compile_filters(flt.get("title_regex_deny", []))
    allow_pats = _compile_filters(flt.get("title_regex_allow", []))
    max_per_src = int(flt.get("max_items_per_source", 0) or 0)

    if deny_pats or allow_pats:
        def _passes(e: Event) -> bool:
            t = e.title or ""
            if deny_pats and any(p.search(t) for p in deny_pats):
                return False
            if allow_pats and not any(p.search(t) for p in allow_pats):
                return False
            return True
        all_events = [e for e in all_events if _passes(e)]

    # Newest first BEFORE the per-source cap: feeds are not all reverse-chronological
    # (CERT-FR lists its oldest alert first), so keeping the N first items of the feed
    # would keep the N oldest and, once they are marked delivered, never reach the
    # recent ones. Entries without a date are treated as most recent and keep their
    # original relative order (the sort is stable).
    _EPOQUE = datetime(1970, 1, 1, tzinfo=timezone.utc)
    _FUTUR = datetime(9999, 12, 31, tzinfo=timezone.utc)

    def _sort_date(e: Event, fallback):
        return _tz_aware(e.published_at) if e.published_at else fallback

    if max_per_src > 0:
        all_events.sort(key=lambda e: _sort_date(e, _FUTUR), reverse=True)

    if max_per_src > 0:
        src_count: Dict[str, int] = defaultdict(int)
        capped: List[Event] = []
        for e in all_events:
            if src_count[e.source] < max_per_src:
                capped.append(e)
                src_count[e.source] += 1
        all_events = capped

    # Chronological order for delivery: the most recent item must arrive last in
    # the channel, where a reader looks first.
    all_events.sort(key=lambda e: _sort_date(e, _EPOQUE))

    # Dedupe & Route
    to_send: Dict[str, Dict[str, List[Event]]] = {}
    route_tpl: Dict[str, str | None] = {}

    from .util import make_event_id

    # Opt-in: an advisory republished under the same URL with a new title or body
    # (CERT-FR "[MaJ]", CISA revisions) is delivered again instead of being silently
    # deduplicated. Off by default: feeds that reword their excerpt would resend.
    resend_on_update = bool(settings.store.get("resend_on_update", False))

    queued: set = set()  # (transport_id, event_id) already scheduled this run
    for ev in all_events:
        eid = make_event_id(ev.source, ev.url, ev.title, getattr(ev, 'dedup_key', None))
        pub_iso = _tz_aware(ev.published_at).astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z") if ev.published_at else None
        revision = store.upsert_event(eid, ev.source, ev.url, ev.title, ev.summary, pub_iso,
                                      tags=ev.tags, meta=public_meta(ev.raw))

        matched_routes = router.match(ev)
        for r in matched_routes:
            for tid in r.transports:
                if (tid, eid) in queued:
                    continue  # overlapping routes / duplicate event -> same transport once
                if not os.environ.get("CTI_NO_DEDUPE") and store.delivered_ok(eid, tid):
                    if not (resend_on_update and revision):
                        continue
                    log.info("resending %s on %s: content changed upstream", eid[:12], tid)

                queued.add((tid, eid))
                to_send.setdefault(r.name, {}).setdefault(tid, []).append(ev)
                route_tpl[r.name] = r.template

    # Send
    sent_total = 0
    for rname, tmap in to_send.items():
        tpl_text = None
        tpl_path = route_tpl.get(rname)
        if tpl_path:
            tpl_path = os.path.expanduser(tpl_path)
        if tpl_path and os.path.exists(tpl_path):
            with open(tpl_path, 'r', encoding='utf-8') as f:
                tpl_text = f.read()
        elif tpl_path:
            log.warning(f"Template not found: {tpl_path}")

        for tid, events in tmap.items():
            tr = transports_by_id.get(tid)
            if not tr:
                continue

            batch_cfg = getattr(tr, 'batch_cfg', {}) if hasattr(tr, 'batch_cfg') else {}
            # Defaults
            max_items = int(batch_cfg.get('max_items', 10)) if batch_cfg.get('enabled') else 1
            # A per-item route template renders only ev0; batching it would
            # silently drop the rest of the chunk (marked delivered, never shown).
            # A template that really uses the `events` variable (batch_default.j2)
            # renders the whole chunk, so batching stays available for it. The
            # variable is looked up by parsing the template: a substring match would
            # be fooled by the word appearing in a comment.
            if tpl_text and not _template_uses_events(tpl_text):
                max_items = 1

            chunks = [[e] for e in events] if max_items <= 1 else [events[i:i + max_items] for i in range(0, len(events), max_items)]

            for chunk in chunks:
                # Determine title based on source name
                # We want the card title to be the SOURCE NAME (e.g. "CERT-FR Avis")
                # The article title will be in the body via template
                if len(chunk) > 0:
                    s = chunk[0].source
                    # Clean up "rss:Name" -> "Name"
                    smart_title = s.replace("rss:", "").replace("ransomware.live", "Ransomware Alert").replace("red.flag.domains", "Red Flag Domains")
                else:
                    smart_title = "CTI Alert"

                try:
                    # Force the source name as the main card title
                    await tr.send(chunk, title=smart_title, template_text=tpl_text)
                    if not dry:
                        for ev in chunk:
                            store.mark_delivery(make_event_id(ev.source, ev.url, ev.title, getattr(ev, 'dedup_key', None)), tid, 'ok')
                        MET_EVENTS.labels(route=rname).inc(len(chunk))
                    sent_total += len(chunk)
                except ValueError as e:
                    log.error(f"Configuration Error for {tid}: {e}")
                    for ev in chunk:
                        store.mark_delivery(make_event_id(ev.source, ev.url, ev.title, getattr(ev, 'dedup_key', None)), tid, 'failed', str(e))
                except Exception as e:
                    log.error(f"Delivery failed to {tid}: {e}", exc_info=True)
                    for ev in chunk:
                        store.mark_delivery(make_event_id(ev.source, ev.url, ev.title, getattr(ev, 'dedup_key', None)), tid, 'failed', str(e))

    log.info(f"Done. Sent {sent_total} events across routes: {len(to_send)}")

    # Post-delivery: periodic LLM briefings recap what was just ingested,
    # prioritised, with links. No-op unless `briefings:` is configured.
    if getattr(settings, "briefings", None):
        try:
            from .briefings import run_briefings
            n = await run_briefings(settings, store, transports_by_id, dry=dry, log=log)
            if n:
                log.info(f"Briefings sent: {n}")
        except Exception as e:
            log.error(f"Briefings step failed: {e}", exc_info=True)

    for tr in transports_by_id.values():
        try:
            await tr.aclose()
        except Exception:
            pass
