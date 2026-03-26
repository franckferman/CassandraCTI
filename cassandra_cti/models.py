# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# models.py
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class Event:
    source: str
    title: str
    url: Optional[str] = None
    summary: str = ""
    published_at: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)
