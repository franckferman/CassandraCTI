# config_schema.py
from __future__ import annotations
from pydantic import BaseModel, Field
from typing import List, Dict, Any


class Feed(BaseModel):
    name: str
    url: str
    tags: List[str] = Field(default_factory=list)


class RSSCfg(BaseModel):
    enabled: bool = True
    feeds: List[Feed] = Field(default_factory=list)


class SettingsModel(BaseModel):
    schema_version: int = 1
    scheduler: Dict[str, Any] = Field(default_factory=dict)
    sources: Dict[str, Any] = Field(default_factory=dict)
    filters: Dict[str, Any] = Field(default_factory=dict)
    transports: Dict[str, Any] = Field(default_factory=dict)
    routes: List[Dict[str, Any]] = Field(default_factory=list)
    store: Dict[str, Any] = Field(default_factory=dict)
    logging: Dict[str, Any] = Field(default_factory=dict)
    metrics: Dict[str, Any] = Field(default_factory=dict)
