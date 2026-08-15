# config_schema.py
from __future__ import annotations
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional


class Feed(BaseModel):
    name: str
    url: str
    tags: List[str] = Field(default_factory=list)


class RSSCfg(BaseModel):
    enabled: bool = True
    feeds: List[Feed] = Field(default_factory=list)


class Route(BaseModel):
    name: str
    include_sources: Optional[List[str]] = None
    include_tags: Optional[List[str]] = None
    include_regex: Optional[str] = None
    include_terms: Optional[List[str]] = None
    transports: List[str] = Field(default_factory=list)
    template: Optional[str] = None


class Briefing(BaseModel):
    name: str
    transports: List[str] = Field(default_factory=list)
    schedule: str = "24h"
    include_sources: Optional[List[str]] = None
    include_tags: Optional[List[str]] = None
    include_regex: Optional[str] = None
    include_terms: Optional[List[str]] = None
    min_items: int = 1
    max_items: int = 40
    top_n: int = 0
    title: Optional[str] = None
    template: Optional[str] = None


class SettingsModel(BaseModel):
    schema_version: int = 1
    scheduler: Dict[str, Any] = Field(default_factory=dict)
    sources: Dict[str, Any] = Field(default_factory=dict)
    filters: Dict[str, Any] = Field(default_factory=dict)
    transports: Dict[str, Any] = Field(default_factory=dict)
    routes: List[Route] = Field(default_factory=list)
    briefings: List[Briefing] = Field(default_factory=list)
    store: Dict[str, Any] = Field(default_factory=dict)
    logging: Dict[str, Any] = Field(default_factory=dict)
    metrics: Dict[str, Any] = Field(default_factory=dict)
