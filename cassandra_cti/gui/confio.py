# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# gui/confio.py
#
# The narrow set of config writes the GUI does directly on the YAML files, for
# settings the CLI has no verb for (the LLM layer) and for the raw-text editor.
# Everything else still goes through the CLI. Writes use ruamel round-trip so a
# hand-written config keeps its comments and layout. No Qt here either.
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from .state import LLMSettings


def read_text(path: Path) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError:
        return ""


def write_text(path: Path, text: str) -> None:
    # Write through a temp file in the same directory, then replace, so a failed
    # write never leaves a half-truncated config behind.
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".cassandra-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, str(path))
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def save_llm(config_path: Path, llm: LLMSettings) -> None:
    """Merge the LLM settings into config.yaml, preserving comments and the rest
    of the file. Uses ruamel (already a project dependency) for the round-trip."""
    from ruamel.yaml import YAML

    path = Path(config_path)
    yaml = YAML()
    yaml.preserve_quotes = True

    data = {}
    if path.exists():
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.load(fh) or {}

    block = data.get("llm")
    if block is None:
        block = {}
        data["llm"] = block

    block["enabled"] = bool(llm.enabled)
    block["provider"] = llm.provider
    block["model"] = llm.model
    block["ollama_base_url"] = llm.ollama_base_url
    block["ollama_model"] = llm.ollama_model
    block["max_tokens"] = int(llm.max_tokens)

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        yaml.dump(data, fh)
