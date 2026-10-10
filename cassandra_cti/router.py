# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# router.py
from __future__ import annotations
import logging
import re
from typing import List, Dict
from .models import Event, public_meta
from .config import RouteDef
from .util import any_term_in


class Router:
    def __init__(self, routes: List[RouteDef], transports_by_id: Dict[str, any]):
        self.routes = routes
        self.transports = transports_by_id
        log = logging.getLogger("cassandra-cti.router")
        self._compiled = {}
        for r in routes:
            if not r.include_regex:
                continue
            try:
                self._compiled[r.name] = re.compile(r.include_regex)
            except re.error as e:
                log.error("route %r has an invalid include_regex %r: %s -- ignored",
                          r.name, r.include_regex, e)

    def match(self, ev: Event) -> List[RouteDef]:
        out: List[RouteDef] = []
        import logging
        logger = logging.getLogger("cassandra-cti.router")

        for r in self.routes:
            ok = False
            reason = ""
            # Check sources
            if r.include_sources:
                for inc in r.include_sources:
                    if inc.endswith(":"):
                        if ev.source.startswith(inc):
                            ok = True
                            reason = f"source_prefix={inc}"
                            break
                    else:
                        if ev.source == inc:
                            ok = True
                            reason = f"source_exact={inc}"
                            break

            # Check tags
            if not ok and r.include_tags:
                if any(t in ev.tags for t in r.include_tags):
                    ok = True
                    reason = "tag_match"

            # Check regex
            if not ok and r.include_regex:
                rgx = self._compiled.get(r.name)
                if rgx and (rgx.search(ev.title or "") or rgx.search(ev.source or "")):
                    ok = True
                    reason = "regex_match"

            # Check plain terms (entity/company watch), matching title + summary +
            # source + tags + meta, accent/case-insensitive.
            if not ok and getattr(r, "include_terms", None):
                hay = " ".join([
                    ev.title or "", ev.summary or "", ev.source or "",
                    " ".join(ev.tags or []),
                    " ".join(str(v) for v in public_meta(ev.raw).values()),
                ])
                if any_term_in(r.include_terms, hay):
                    ok = True
                    reason = "term_match"

            if ok:
                logger.debug(f"Route '{r.name}' matched event '{ev.title}' (source={ev.source}) via {reason}. Transports: {r.transports}")
                out.append(r)
        return out
