# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# gui/forms.py
#
# Pure data: the form schema the app renders. No Qt. Adding a CLI flag means
# adding a Field here; app.py builds the widget from `kind`. Flags mirror the
# real `cassandra <subcmd> --help`.
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Field:
    kind: str                    # 'line' | 'text' | 'spin' | 'combo' | 'check'
    name: str                    # CLI option name without '--'; '' for positional
    label: str
    default: object = ""
    choices: tuple = ()          # combo values, or (min, max) for spin
    is_positional: bool = False
    help: str = ""


@dataclass(frozen=True)
class Form:
    subcmd: str
    description: str
    positional: tuple = ()
    options: tuple = ()


# Path options are per-form, not global: this CLI has no flag every subcommand
# accepts (add-connector takes --connectors but not --config, and so on), so a
# shared group would emit flags some subcommands reject.
_CONFIG = Field("line", "config", "config path", help="path to config.yaml")
_CONNECTORS = Field("line", "connectors", "connectors path", help="path to connectors.yaml")

COMMON_OPTIONS: tuple = ()       # intentionally empty, see note above

_SOURCE_KINDS = ("rss", "ransomware.live", "red-flag-domains", "cisa-kev", "abusech")
_CONNECTOR_KINDS = ("teams", "discord", "telegram", "smtp", "signal", "web")

FORMS: dict = {
    "init": Form(
        "init", "Scaffold config.yaml and connectors.yaml.",
        options=(_CONFIG, _CONNECTORS),
    ),
    "run": Form(
        "run", "Run the pipeline once, or loop on an interval.",
        options=(
            Field("check", "loop", "loop", default=False, help="keep running on an interval"),
            Field("spin", "interval", "interval (s)", default=300, choices=(5, 86400)),
            Field("check", "web", "web dashboard", default=False),
            Field("line", "web-host", "web host", default="127.0.0.1"),
            Field("spin", "web-port", "web port", default=8080, choices=(1, 65535)),
            Field("line", "sources", "only sources", help="comma-separated source filter"),
            Field("line", "since", "since", help="ISO date lower bound"),
            Field("check", "dry-run", "dry run", default=False),
            Field("check", "verbose", "verbose", default=False),
            Field("check", "no-dedupe", "no dedupe", default=False),
            _CONFIG, _CONNECTORS,
        ),
    ),
    "doctor": Form(
        "doctor", "Validate config, test a connector, or probe every feed.",
        positional=(
            Field("combo", "", "kind", default="config",
                  choices=("config", "connector", "feeds"), is_positional=True),
        ),
        options=(
            Field("line", "id", "connector id", help="required for 'doctor connector'"),
            Field("spin", "stale-days", "stale days", default=60, choices=(1, 3650)),
            _CONFIG, _CONNECTORS,
        ),
    ),
    "list": Form(
        "list", "List configured sources, connectors, routes and briefings.",
        options=(_CONFIG, _CONNECTORS),
    ),
    "add-source": Form(
        "add-source", "Enable a data source.",
        positional=(
            Field("combo", "", "kind", default="rss", choices=_SOURCE_KINDS, is_positional=True),
        ),
        options=(
            Field("line", "name", "feed name", help="RSS only"),
            Field("line", "url", "feed url", help="RSS only"),
            Field("line", "tags", "tags", help="comma-separated"),
            Field("line", "api-key", "api key", help="PRO tiers / abuse.ch"),
            Field("line", "feeds", "feeds csv", help="bulk import path"),
            _CONFIG,
        ),
    ),
    "add-connector": Form(
        "add-connector", "Add a delivery connector.",
        options=(
            Field("line", "id", "connector id"),
            Field("combo", "type", "type", default="teams", choices=_CONNECTOR_KINDS),
            Field("line", "webhook-url", "webhook url", help="teams / discord"),
            Field("line", "theme-color", "theme color", default="0078D7"),
            Field("check", "emojis", "emojis", default=True),
            Field("line", "bot-token", "bot token", help="telegram"),
            Field("line", "chat-id", "chat id", help="telegram"),
            _CONNECTORS,
        ),
    ),
    "routes-add": Form(
        "routes-add", "Add or update a route.",
        options=(
            Field("line", "name", "route name"),
            Field("line", "include-tag", "include tag"),
            Field("line", "include", "include source"),
            Field("line", "include-regex", "include regex"),
            Field("line", "transports", "transports", help="comma-separated connector ids"),
            Field("line", "template", "template", default="templates/rss_default.j2"),
            _CONFIG,
        ),
    ),
    "channel-add": Form(
        "channel-add", "Wire a connector, a route and an optional briefing at once.",
        options=(
            Field("line", "name", "channel name"),
            Field("line", "webhook-url", "webhook url"),
            Field("combo", "type", "type", default="teams", choices=("teams", "discord")),
            Field("line", "tag", "tag", help="defaults to name"),
            Field("line", "source", "source", help="route a source instead of a tag"),
            Field("line", "theme-color", "theme color", default="0078D7"),
            Field("spin", "batch", "batch size", default=0, choices=(0, 100)),
            Field("line", "template", "template"),
            Field("check", "no-route", "no route", default=False, help="briefing-only channel"),
            Field("line", "brief-at", "brief at", help="e.g. 08:00"),
            Field("line", "brief-to", "brief to", help="connector id for the recap"),
            Field("spin", "brief-top-n", "brief top-n", default=5, choices=(0, 50)),
            Field("spin", "brief-min-items", "brief min items", default=3, choices=(1, 100)),
            _CONFIG, _CONNECTORS,
        ),
    ),
    "briefing-add": Form(
        "briefing-add", "Add a periodic LLM briefing.",
        options=(
            Field("line", "name", "briefing name"),
            Field("line", "include", "include source"),
            Field("line", "include-tag", "include tag"),
            Field("line", "transports", "transports"),
            Field("line", "schedule", "schedule", default="24h"),
            Field("line", "at", "at", help="wall-clock time, e.g. 08:00"),
            Field("spin", "min-items", "min items", default=1, choices=(1, 100)),
            Field("spin", "max-items", "max items", default=40, choices=(1, 500)),
            Field("spin", "top-n", "top-n", default=0, choices=(0, 50)),
            Field("text", "focus", "focus", help="what 'important' means for this channel"),
            Field("line", "title", "title"),
            _CONFIG,
        ),
    ),
    "briefing-run": Form(
        "briefing-run", "Send briefings now (due ones, or forced).",
        options=(
            Field("line", "name", "briefing name", help="force one by name"),
            Field("check", "all", "all", default=False, help="force every briefing"),
            Field("check", "dry-run", "dry run", default=False),
            _CONFIG, _CONNECTORS,
        ),
    ),
    "backfill": Form(
        "backfill", "Replay stored events to a transport.",
        options=(
            Field("line", "to", "to transport", help="connector id"),
            Field("line", "since", "since", help="ISO date"),
            _CONFIG, _CONNECTORS,
        ),
    ),
}


def subcommands() -> list:
    return list(FORMS.keys())
