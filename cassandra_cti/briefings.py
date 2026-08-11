# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# briefings.py
#
# Periodic LLM briefings: a post-delivery step that, per configured briefing,
# gathers the events ingested since the last brief (matching the same selectors
# as routes), asks the LLM to PRIORITISE + narrate them with links, and sends
# ONE recap through an existing transport — after the individual alerts went out.
#
# Optional and off unless `briefings:` is configured AND the `llm:` layer can
# resolve a provider. Honours CTI_DRY_RUN (prints [DRYRUN:BRIEFING], no calls).
from __future__ import annotations
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .llm import LLM, LLMError
from .models import Event

_DUR = re.compile(r"^\s*(\d+)\s*([smhd])\s*$")
_UNIT = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_schedule(s: str) -> timedelta:
    """'24h' / '6h' / '30m' / '2d' -> timedelta. Defaults to 24h on garbage."""
    m = _DUR.match(str(s or "24h").lower())
    if not m:
        return timedelta(hours=24)
    return timedelta(**{_UNIT[m.group(2)]: int(m.group(1))})


def schedule_label(s: str) -> str:
    td = parse_schedule(s)
    secs = int(td.total_seconds())
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if secs % n == 0 and secs >= n:
            return f"{secs // n}{unit}"
    return f"{secs}s"


def matches(b, row: Dict[str, Any]) -> bool:
    """OR across include_sources / include_tags / include_regex — mirrors the
    Router. A briefing with no selector matches everything (a firehose recap)."""
    src = row.get("source") or ""
    tags = row.get("tags") or []
    if not (b.include_sources or b.include_tags or b.include_regex):
        return True
    if b.include_sources:
        for inc in b.include_sources:
            if inc.endswith(":"):
                if src.startswith(inc):
                    return True
            elif src == inc:
                return True
    if b.include_tags and any(t in tags for t in b.include_tags):
        return True
    if b.include_regex:
        try:
            rgx = re.compile(b.include_regex)
            if rgx.search(row.get("title") or "") or rgx.search(src):
                return True
        except re.error:
            pass
    return False


_SYSTEM = (
    "You are a SOC shift lead writing a short briefing for a threat-intel channel. "
    "You are given the items that came in since the last briefing. Produce: "
    "(1) one or two sentences of overview; (2) a short 'Priorities' section listing the "
    "2-4 most important items, each on its own line as '<what it is and why it matters> - <URL>'; "
    "(3) optionally one closing line for the rest. Put the raw URL after each priority so it stays "
    "clickable. Prioritise actively-exploited CVEs, ransomware-linked items and high-confidence "
    "IOCs over general news. Write plain text only: no Markdown, no bold or asterisks, no headings, "
    "no numbered or bulleted list markers. Be specific and concise."
)


def _event_line(e: Dict[str, Any]) -> str:
    meta = e.get("meta") or {}
    sig: List[str] = []
    for k, label in (("cve", None), ("group_name", "group"), ("malware", "malware"),
                     ("vendor", "vendor"), ("ioc_type", "ioc")):
        v = meta.get(k)
        if v:
            sig.append(str(v) if label is None else f"{label}={v}")
    if meta.get("ransomware_use"):
        sig.append("ransomware-linked")
    tail = f" [{', '.join(sig)}]" if sig else ""
    url = f" - {e.get('url')}" if e.get("url") else ""
    return f"- {e.get('source')}: {e.get('title')}{tail}{url}"


async def _make_brief(llm: LLM, b, events: List[Dict[str, Any]], period_label: str) -> str:
    items = events[: b.max_items]
    body = "\n".join(_event_line(e) for e in items)
    prompt = (f"Channel: {b.name}\nWindow: last {period_label}\n"
              f"Items ({len(items)}):\n{body}")
    return await llm.complete(prompt, system=_SYSTEM)


def _load_template(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    p = os.path.expanduser(path)
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8") as f:
            return f.read()
    return None


async def run_briefings(settings, store, transports_by_id: Dict[str, Any],
                        dry: bool = False, log=None, llm: Optional[LLM] = None,
                        force_names: Optional[set] = None, force_all: bool = False,
                        now: Optional[datetime] = None) -> int:
    """Check every configured briefing; send those that are due (or forced).
    Returns the number of briefings sent (or, in dry-run, that would send)."""
    briefings = list(getattr(settings, "briefings", []) or [])
    if not briefings:
        return 0
    now = now or _now()
    llm = llm or LLM(getattr(settings, "llm", {}) or {})
    sent = 0

    for b in briefings:
        forced = force_all or (force_names is not None and b.name in force_names)
        period = parse_schedule(b.schedule)
        last = store.briefing_last_sent(b.name)
        if last:
            last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
            since_dt = last_dt
            due = (now - last_dt) >= period
        else:
            since_dt = now - period          # first run: cover the last period
            due = True
        if not (due or forced):
            continue

        hi = now + timedelta(seconds=1)       # include just-ingested events
        window = store.events_between(_iso(since_dt), _iso(hi))
        events = [e for e in window if matches(b, e)]
        if len(events) < max(1, b.min_items) and not forced:
            continue                          # too little to be worth a brief; retry later

        label = schedule_label(b.schedule)
        if dry:
            if log:
                log.info(f"[DRYRUN:BRIEFING] {b.name} -> {b.transports} "
                         f"({len(events)} items, since {_iso(since_dt)})")
            print(f"[DRYRUN:BRIEFING] {b.name} -> {b.transports} ({len(events)} items)")
            sent += 1
            continue

        try:
            text = await _make_brief(llm, b, events, label)
        except LLMError as e:
            if log:
                log.error(f"briefing '{b.name}': LLM unavailable ({e}) -- skipped")
            continue
        if not text:
            continue

        title = b.title or f"Briefing: {b.name} ({len(events)} items, last {label})"
        tpl = _load_template(b.template)
        ev = Event(source=b.name, title=title, url=None, summary=text,
                   tags=["briefing"], raw={"kind": "briefing", "count": len(events)})

        delivered = False
        for tid in b.transports:
            tr = transports_by_id.get(tid)
            if not tr:
                if log:
                    log.warning(f"briefing '{b.name}': unknown transport '{tid}'")
                continue
            try:
                await tr.send([ev], title=title, template_text=tpl)
                delivered = True
            except Exception as e:  # noqa: BLE001 - one bad transport must not sink the rest
                if log:
                    log.error(f"briefing '{b.name}' -> {tid} failed: {e}")

        if delivered:
            store.mark_briefing_sent(b.name, _iso(now))
            sent += 1

    return sent
