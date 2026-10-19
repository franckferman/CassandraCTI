# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# tests/test_llm.py
#
# The LLM layer's provider-selection and prompt-building logic, offline. The
# conftest network guard makes ollama_status() report unreachable (its probe
# raises and is swallowed), so resolve() deterministically exercises the cloud
# key / model fallbacks without ever touching the network.
import asyncio

import pytest

from cassandra_cti.llm import LLM, LLMError, _CLOUD

CLOUD_KEYS = [meta["key"] for meta in _CLOUD.values()]


def _clear_cloud_env(monkeypatch):
    # Drop any ambient cloud keys so a developer's real environment cannot
    # change the outcome of a "no key set" assertion.
    for key in CLOUD_KEYS:
        monkeypatch.delenv(key, raising=False)


def test_cloud_key_prefers_config_over_env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "from-env")
    llm = LLM({"anthropic_api_key": "from-config"})
    assert llm._cloud_key("anthropic") == "from-config"
    # Falls back to the env var when config has none.
    llm2 = LLM({})
    assert llm2._cloud_key("anthropic") == "from-env"


def test_cloud_key_absent(monkeypatch):
    _clear_cloud_env(monkeypatch)
    assert LLM({})._cloud_key("openai") == ""


def test_cloud_model_override_and_default():
    assert LLM({"model": "custom-x"})._cloud_model("openai") == "custom-x"
    assert LLM({})._cloud_model("openai") == _CLOUD["openai"]["default_model"]
    assert LLM({})._cloud_model("anthropic") == _CLOUD["anthropic"]["default_model"]


def test_resolve_explicit_cloud_with_key(monkeypatch):
    _clear_cloud_env(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    r = asyncio.run(LLM({"provider": "anthropic"}).resolve())
    assert r["available"] is True
    assert r["provider"] == "anthropic"
    assert r["model"] == _CLOUD["anthropic"]["default_model"]
    assert r["configured"] == "anthropic"
    # ollama is unreachable under the offline guard.
    assert r["providers"]["ollama"] is False


def test_resolve_explicit_cloud_without_key(monkeypatch):
    _clear_cloud_env(monkeypatch)
    r = asyncio.run(LLM({"provider": "openai"}).resolve())
    assert r["available"] is False
    assert r["provider"] is None


def test_resolve_auto_picks_first_available_cloud_key(monkeypatch):
    _clear_cloud_env(monkeypatch)
    # Only deepseek has a key, so auto (ollama unreachable) must land on it.
    monkeypatch.setenv("DEEPSEEK_API_KEY", "k")
    r = asyncio.run(LLM({"provider": "auto"}).resolve())
    assert r["provider"] == "deepseek"
    assert r["model"] == _CLOUD["deepseek"]["default_model"]


def test_resolve_ollama_unreachable_is_unavailable(monkeypatch):
    _clear_cloud_env(monkeypatch)
    r = asyncio.run(LLM({"provider": "ollama"}).resolve())
    assert r["available"] is False
    assert r["provider"] is None


def test_complete_without_provider_raises(monkeypatch):
    _clear_cloud_env(monkeypatch)
    with pytest.raises(LLMError):
        asyncio.run(LLM({"provider": "ollama"}).complete("hello"))


def test_summarize_event_builds_prompt(monkeypatch):
    captured = {}

    async def fake_complete(self, prompt, system=None):
        captured["prompt"] = prompt
        captured["system"] = system
        return "ok"

    monkeypatch.setattr(LLM, "complete", fake_complete)
    ev = {
        "source": "cisa.kev",
        "title": "Fortinet auth bypass",
        "summary": "Added to the KEV catalog.",
        "meta": {"cve": "CVE-2025-1234", "vendor": "Fortinet", "product": "FortiOS",
                 "ioc": "", "group_name": None},
    }
    out = asyncio.run(LLM({}).summarize_event(ev))
    assert out == "ok"
    p = captured["prompt"]
    assert "Source: cisa.kev" in p
    assert "Title: Fortinet auth bypass" in p
    assert "Summary: Added to the KEV catalog." in p
    assert "cve: CVE-2025-1234" in p
    assert "vendor: Fortinet" in p
    # Empty / None meta fields are skipped, not rendered.
    assert "ioc:" not in p
    assert "group_name:" not in p
    # System prompt pins the plain-prose, no-Markdown contract the UI relies on.
    assert "SOC analyst" in captured["system"]
    assert "no Markdown" in captured["system"]
