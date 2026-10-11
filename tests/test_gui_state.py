# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# tests/test_gui_state.py
#
# The GUI's Qt-free layers: reading the workspace (state.py), the theme string
# (theme.py), and the config writes (confio.py). No Qt, no display, no core.
from pathlib import Path

from cassandra_cti.gui import confio, state, theme

CONFIG = """\
schema_version: 1
scheduler:
  mode: oneshot
  max_concurrent_fetches: 8
sources:
  rss:
    enabled: true
    user_agent: cassandra
    feeds:
      - { name: "A", url: "https://a/feed", tags: ["news"] }
      - { name: "B", url: "https://b/feed", tags: ["cert"] }
  ransomware.live:
    enabled: true
    lookback_days: 30
  cisa.kev:
    enabled: false
    max_items: 80
routes:
  - name: ransomware
    include_sources: ["ransomware.live"]
    transports: ["teams-rw", "discord"]
  - name: certs
    include_tags: ["cert"]
    transports: ["teams-cert"]
briefings:
  - name: daily
    schedule: "24h"
    transports: ["teams-brief"]
    include_tags: ["vuln"]
store:
  sqlite_path: .cassandra_cti.db
llm:
  enabled: true
  provider: ollama
  model: ""
  ollama_base_url: http://localhost:11434
  ollama_model: llama3
  max_tokens: 500
"""

CONNECTORS = """\
connectors:
  - { id: teams-rw, type: teams }
  - { id: discord, type: discord }
  - { id: teams-cert, type: teams }
"""


def _write(tmp_path):
    cfg = tmp_path / "config.yaml"
    cx = tmp_path / "connectors.yaml"
    cfg.write_text(CONFIG, encoding="utf-8")
    cx.write_text(CONNECTORS, encoding="utf-8")
    return cfg, cx


def test_load_workspace_counts(tmp_path):
    cfg, cx = _write(tmp_path)
    ws = state.load_workspace(cfg, cx)
    assert ws.config_exists and ws.connectors_exists
    assert len(ws.sources) == 3
    assert ws.enabled_sources == 2
    assert len(ws.routes) == 2
    assert len(ws.briefings) == 1
    assert len(ws.connectors) == 3
    assert ws.max_concurrent_fetches == 8
    assert ws.store_db == ".cassandra_cti.db"


def test_load_workspace_source_detail(tmp_path):
    cfg, cx = _write(tmp_path)
    ws = state.load_workspace(cfg, cx)
    rss = next(s for s in ws.sources if s.key == "rss")
    assert rss.enabled is True
    assert rss.feed_count == 2
    assert rss.label == "RSS feeds"
    kev = next(s for s in ws.sources if s.key == "cisa.kev")
    assert kev.enabled is False
    assert "max_items=80" in kev.detail
    assert kev.label == "CISA KEV"


def test_load_workspace_llm(tmp_path):
    cfg, cx = _write(tmp_path)
    ws = state.load_workspace(cfg, cx)
    assert ws.llm.enabled is True
    assert ws.llm.provider == "ollama"
    assert ws.llm.ollama_model == "llama3"
    assert ws.llm.max_tokens == 500


def test_load_workspace_selectors(tmp_path):
    cfg, cx = _write(tmp_path)
    ws = state.load_workspace(cfg, cx)
    rw = next(r for r in ws.routes if r.name == "ransomware")
    assert "src=ransomware.live" in rw.selector
    certs = next(r for r in ws.routes if r.name == "certs")
    assert "tags=cert" in certs.selector


def test_load_workspace_missing_files(tmp_path):
    ws = state.load_workspace(tmp_path / "nope.yaml", tmp_path / "none.yaml")
    assert ws.config_exists is False
    assert ws.connectors_exists is False
    assert ws.sources == []
    assert ws.connectors == []
    # Defaults still present.
    assert ws.llm.provider == "auto"


def test_load_workspace_malformed_is_not_fatal(tmp_path):
    bad = tmp_path / "config.yaml"
    bad.write_text("this: : : not valid yaml\n  - broken", encoding="utf-8")
    ws = state.load_workspace(bad, tmp_path / "cx.yaml")
    # Malformed file parses to empty, not an exception.
    assert ws.sources == []


def test_default_config_dir_is_path():
    assert isinstance(state.default_config_dir(), Path)


def test_theme_stylesheet_has_palette():
    css = theme.stylesheet()
    assert isinstance(css, str) and len(css) > 500
    assert theme.AMBER in css
    assert theme.BG in css
    assert "QListWidget#nav" in css


def test_theme_dark_and_light_differ():
    dark = theme.stylesheet("dark")
    light = theme.stylesheet("light")
    assert dark != light
    assert theme._DARK["bg"] in dark
    assert theme._LIGHT["bg"] in light
    # Anything that is not 'light' resolves to the dark palette.
    assert theme.stylesheet("system") == dark
    assert theme.stylesheet("nonsense") == dark


def test_theme_palette_is_a_copy():
    p = theme.palette("dark")
    p["bg"] = "#000000"
    assert theme.palette("dark")["bg"] != "#000000"


def test_confio_text_roundtrip(tmp_path):
    path = tmp_path / "sub" / "config.yaml"
    confio.write_text(path, "hello: world\n")
    assert confio.read_text(path) == "hello: world\n"
    assert confio.read_text(tmp_path / "absent.yaml") == ""


def test_confio_save_llm_preserves_other_keys(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(CONFIG, encoding="utf-8")
    new = state.LLMSettings(enabled=False, provider="anthropic", model="claude",
                            ollama_base_url="http://x", ollama_model="", max_tokens=42)
    confio.save_llm(cfg, new)
    ws = state.load_workspace(cfg, tmp_path / "cx.yaml")
    # LLM block updated.
    assert ws.llm.provider == "anthropic"
    assert ws.llm.model == "claude"
    assert ws.llm.max_tokens == 42
    # The rest of the config survived the write.
    assert len(ws.sources) == 3
    assert len(ws.routes) == 2


def test_confio_save_llm_creates_block_when_absent(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("sources:\n  rss:\n    enabled: true\n", encoding="utf-8")
    new = state.LLMSettings(enabled=True, provider="openai")
    confio.save_llm(cfg, new)
    ws = state.load_workspace(cfg, tmp_path / "cx.yaml")
    assert ws.llm.enabled is True
    assert ws.llm.provider == "openai"
