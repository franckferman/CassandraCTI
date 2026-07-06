# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# transports/__init__.py
from __future__ import annotations
from .teams import TeamsTransport
from .discord import DiscordTransport
from .telegram import TelegramTransport
from .smtp import SMTPTransport

REGISTRY = {
    "teams": TeamsTransport,
    "discord": DiscordTransport,
    "telegram": TelegramTransport,
    "smtp": SMTPTransport,
}


def build_transport(ttype: str, params: dict):
    cls = REGISTRY.get(ttype)
    if not cls:
        raise ValueError(f"Unknown transport type: {ttype}")
    return cls(**params)
