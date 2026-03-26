# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# sources/__init__.py
from __future__ import annotations
from typing import Dict, Any
from .rss import build_rss_sources
from .ransomware_live import RansomwareLive
from .redflag import RedFlagDomains


async def build_sources(cfg: Dict[str, Any]):
    out = []
    scfg = cfg.get("sources", {})
    if scfg.get("rss", {}).get("enabled"):
        out.extend(build_rss_sources(scfg["rss"]))
    if scfg.get("ransomware_live", {}).get("enabled"):
        rl_cfg = scfg["ransomware_live"]
        out.append(RansomwareLive(
            url=rl_cfg.get("url", "https://data.ransomware.live/posts.json"),
            lookback_days=int(rl_cfg.get("lookback_days", 30)),
        ))
    if scfg.get("red_flag_domains", {}).get("enabled"):
        rf_cfg = scfg["red_flag_domains"]
        out.append(RedFlagDomains(
            base_url=rf_cfg.get("base_url", "https://dl.red.flag.domains/daily/"),
        ))
    return out
