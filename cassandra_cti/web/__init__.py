# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# web/__init__.py
from __future__ import annotations
from .app import DashboardHub, WebDashboardServer, create_app, get_server

__all__ = ["DashboardHub", "WebDashboardServer", "create_app", "get_server"]
