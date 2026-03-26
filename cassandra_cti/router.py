# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# router.py
from __future__ import annotations
import re
from typing import List, Dict
from .models import Event
from .config import RouteDef


class Router:
    def __init__(self, routes: List[RouteDef], transports_by_id: Dict[str, any]):
        self.routes = routes
        self.transports = transports_by_id
        self._compiled = {r.name: re.compile(r.include_regex) for r in routes if r.include_regex}

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

            if ok:
                logger.debug(f"Route '{r.name}' matched event '{ev.title}' (source={ev.source}) via {reason}. Transports: {r.transports}")
                out.append(r)
        return out
