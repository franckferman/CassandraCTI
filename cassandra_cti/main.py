# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# main.py
from __future__ import annotations
import os
import re
import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List
from .config import load_settings
from .store import Store
from .sources import build_sources
from .transports import build_transport
from .router import Router
from .models import Event
from prometheus_client import Counter, start_http_server

MET_EVENTS = Counter('cassandra_cti_events_sent', 'Events sent', ['route'])
MET_FETCH = Counter('cassandra_cti_fetch_total', 'Fetch by source', ['source', 'status'])


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


async def run_once(settings_path: str, connectors_path: str | None = None, only_sources: list[str] | None = None):
    settings = load_settings(settings_path, connectors_path)

    lvl = os.environ.get("CTI_LOGLEVEL") or settings.logging.get("level", "INFO")
    logging.basicConfig(level=getattr(logging, lvl))
    log = logging.getLogger("cassandra-cti")

    if settings.metrics.get('enabled') and not os.environ.get('CTI_METRICS_STARTED'):
        try:
            start_http_server(port=settings.metrics.get('port', 9108), addr=settings.metrics.get('host', '0.0.0.0'))
            os.environ['CTI_METRICS_STARTED'] = '1'
        except Exception as e:
            log.warning(f"Metrics server error: {e}")

    # Resolve DB path relative to config file if relative
    db_path_str = settings.store.get("sqlite_path", ".cassandra_cti.db")
    import pathlib
    db_path = pathlib.Path(db_path_str)
    if not db_path.is_absolute():
        # Resolve relative to config file location
        conf_dir = pathlib.Path(settings_path).parent
        db_path = conf_dir / db_path

    store = Store(str(db_path))

    ttl = int(settings.store.get("seen_ttl_days", 0) or 0)
    if ttl > 0:
        store.purge_ttl(ttl)

    transports_by_id: Dict[str, Any] = {}
    for tdef in settings.transports:
        try:
            tr = build_transport(tdef.type, tdef.params)
            transports_by_id[tdef.id] = tr
        except Exception as e:
            log.error(f"Failed to build transport {tdef.id}: {e}")

    router = Router(settings.routes, transports_by_id)

    sources = await build_sources({"sources": settings.sources})
    if only_sources:
        src_set = set(only_sources)
        sources = [s for s in sources if any(
            getattr(s, "source", "").startswith(tag) or getattr(s, "source", "") == tag for tag in src_set
        )]

    async def _fetch(s):
        try:
            evs = await s.fetch()
            for _ in evs:
                MET_FETCH.labels(source=getattr(s, 'source', 'unknown'), status='ok').inc()
            return evs
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
    deny_pats = [re.compile(p, re.IGNORECASE) for p in flt.get("title_regex_deny", []) if p]
    allow_pats = [re.compile(p, re.IGNORECASE) for p in flt.get("title_regex_allow", []) if p]
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

    if max_per_src > 0:
        src_count: Dict[str, int] = defaultdict(int)
        capped: List[Event] = []
        for e in all_events:
            if src_count[e.source] < max_per_src:
                capped.append(e)
                src_count[e.source] += 1
        all_events = capped

    # Dedupe & Route
    to_send: Dict[str, Dict[str, List[Event]]] = {}
    route_tpl: Dict[str, str | None] = {}

    from .util import make_event_id

    for ev in all_events:
        eid = make_event_id(ev.source, ev.url, ev.title)
        pub_iso = _tz_aware(ev.published_at).isoformat(timespec="seconds").replace("+00:00", "Z") if ev.published_at else None
        store.upsert_event(eid, ev.source, ev.url, ev.title, ev.summary, pub_iso)

        matched_routes = router.match(ev)
        for r in matched_routes:
            for tid in r.transports:
                if not os.environ.get("CTI_NO_DEDUPE") and store.delivered_ok(eid, tid):
                    continue

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

            chunks = [[e] for e in events] if max_items <= 1 else [events[i:i + max_items] for i in range(0, len(events), max_items)]

            for chunk in chunks:
                # Determine title based on source name
                # We want the card title to be the SOURCE NAME (e.g. "FR-CERT Avis")
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
                    for ev in chunk:
                        store.mark_delivery(make_event_id(ev.source, ev.url, ev.title), tid, 'ok')
                    MET_EVENTS.labels(route=rname).inc(len(chunk))
                    sent_total += len(chunk)
                except ValueError as e:
                    log.error(f"Configuration Error for {tid}: {e}")
                    for ev in chunk:
                        store.mark_delivery(make_event_id(ev.source, ev.url, ev.title), tid, 'failed', str(e))
                except Exception as e:
                    log.error(f"Delivery failed to {tid}: {e}", exc_info=True)
                    for ev in chunk:
                        store.mark_delivery(make_event_id(ev.source, ev.url, ev.title), tid, 'failed', str(e))

    log.info(f"Done. Sent {sent_total} events across routes: {len(to_send)}")

    for tr in transports_by_id.values():
        try:
            await tr.aclose()
        except Exception:
            pass
