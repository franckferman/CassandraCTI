# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# util.py
from __future__ import annotations
import os
import re
import hashlib
from url_normalize import url_normalize

_env_pattern = re.compile(r"\$\{([A-Z0-9_]+)\}")
TRACKERS = re.compile(r'([?&])(utm_[^=]+|fbclid|gclid|mc_cid|mc_eid)=[^&]+')


def expand_env(value: str) -> str:
    if not isinstance(value, str):
        return value

    def _repl(m):
        return os.environ.get(m.group(1), m.group(0))
    return _env_pattern.sub(_repl, value)


def canon(url: str | None) -> str:
    if not url:
        return ""
    try:
        u = url_normalize(url)
    except Exception:
        u = url
    # Strip tracking params so the same article dedups regardless of utm_*/fbclid/...
    u = TRACKERS.sub(lambda m: m.group(1), u)
    u = re.sub(r"[?&]+$", "", u).replace("?&", "?").replace("&&", "&")
    return u


def make_event_id(source: str, url: str | None, title: str) -> str:
    # Use title as fallback if url is missing
    base = f"{source}|{canon(url)}" if url else f"{source}|{(title or '').strip()}"
    return hashlib.sha1(base.encode('utf-8'), usedforsecurity=False).hexdigest()


def resolve_db_path(sqlite_path: str | None, config_path: str | None) -> str:
    """Resolve the SQLite store path.

    When ``sqlite_path`` is relative it is anchored to the directory of the
    config file, so every command (run, backfill, seen-clear, db-reset) targets
    the exact same database regardless of the current working directory.
    """
    import pathlib
    p = pathlib.Path(sqlite_path or ".cassandra_cti.db")
    if not p.is_absolute() and config_path:
        p = pathlib.Path(config_path).parent / p
    return str(p)
