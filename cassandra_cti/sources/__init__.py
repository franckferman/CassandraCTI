# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# sources/__init__.py
from __future__ import annotations
from typing import Dict, Any
from .rss import build_rss_sources
from .ransomware_live import RansomwareLive
from .ransomware_press import RansomwarePress
from .ransomware_8k import Ransomware8K
from .ransomware_stats import RansomwareStats
from .redflag import RedFlagDomains
from .cisa_kev import CisaKev
from .abusech import AbuseCh


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
            api_key=rl_cfg.get("api_key"),
            pro_base=rl_cfg.get("pro_base", "https://api-pro.ransomware.live"),
            v2_base=rl_cfg.get("v2_base", "https://api.ransomware.live/v2"),
        ))
    if scfg.get("ransomware_press", {}).get("enabled"):
        p_cfg = scfg["ransomware_press"]
        out.append(RansomwarePress(api_key=p_cfg.get("api_key"), country=p_cfg.get("country")))
    if scfg.get("ransomware_8k", {}).get("enabled"):
        out.append(Ransomware8K(api_key=scfg["ransomware_8k"].get("api_key")))
    if scfg.get("ransomware_stats", {}).get("enabled"):
        out.append(RansomwareStats(api_key=scfg["ransomware_stats"].get("api_key")))
    if scfg.get("red_flag_domains", {}).get("enabled"):
        rf_cfg = scfg["red_flag_domains"]
        out.append(RedFlagDomains(
            base_url=rf_cfg.get("base_url", "https://dl.red.flag.domains/daily/"),
        ))
    if scfg.get("cisa_kev", {}).get("enabled"):
        k_cfg = scfg["cisa_kev"]
        out.append(CisaKev(
            lookback_days=int(k_cfg.get("lookback_days", 365)),
            max_items=int(k_cfg.get("max_items", 80)),
        ))
    if scfg.get("abusech", {}).get("enabled"):
        a_cfg = scfg["abusech"]
        out.append(AbuseCh(
            api_key=a_cfg.get("api_key"),
            feeds=a_cfg.get("feeds"),
            max_items=int(a_cfg.get("max_items", 60)),
        ))
    return out
