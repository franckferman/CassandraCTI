# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# llm.py
#
# Optional, provider-agnostic LLM layer for AI-assisted features (event
# briefs / triage). Providers: ollama (local, free, private), anthropic,
# openai, deepseek, all behind one `complete(prompt) -> str`. Disabled by
# default; nothing calls out unless a feature invokes complete()/status().
#
# provider = "auto"  -> a reachable local Ollama first (free/private), else the
#                       first cloud key that is set.
# provider = "<name>"-> that provider only (clear error if unavailable).
#
# Design ported from the Bikochu recon platform's llm layer, adapted to
# aiohttp (already a CassandraCTI dependency) and current Claude model IDs.
from __future__ import annotations
import os
import socket
from typing import Any, Dict, Optional

import aiohttp

from .net import ssl_ctx

# Cloud providers: env key + a sensible default model. Model can be overridden
# via `llm.model` in config.
_CLOUD = {
    "anthropic": {"key": "ANTHROPIC_API_KEY", "default_model": "claude-opus-5"},
    "openai": {"key": "OPENAI_API_KEY", "default_model": "gpt-4o-mini"},
    "deepseek": {"key": "DEEPSEEK_API_KEY", "default_model": "deepseek-chat"},
}
PROVIDERS = ["ollama", *_CLOUD.keys()]


class LLMError(Exception):
    """Raised when no provider is available or a provider call fails."""


class LLM:
    def __init__(self, cfg: Optional[Dict[str, Any]] = None):
        cfg = cfg or {}
        self.enabled = bool(cfg.get("enabled"))
        self.provider = (cfg.get("provider") or "auto").lower()
        self.model = (cfg.get("model") or "").strip() or None
        self.ollama_base_url = (cfg.get("ollama_base_url") or "http://localhost:11434").rstrip("/")
        self.ollama_model = (cfg.get("ollama_model") or "").strip() or None
        self.max_tokens = int(cfg.get("max_tokens", 512))
        self._cfg = cfg

    # ---- key resolution ---------------------------------------------------
    def _cloud_key(self, provider: str) -> str:
        meta = _CLOUD.get(provider) or {}
        # Config (env-expanded at load time) takes precedence, else the env var.
        val = self._cfg.get(f"{provider}_api_key") or os.environ.get(meta.get("key", ""), "")
        return (val or "").strip()

    def _cloud_model(self, provider: str) -> str:
        return self.model or (_CLOUD.get(provider) or {}).get("default_model", "")

    def _conn(self):
        return aiohttp.TCPConnector(family=socket.AF_INET, ssl=ssl_ctx())

    # ---- ollama probe -----------------------------------------------------
    async def ollama_status(self) -> Dict[str, Any]:
        try:
            async with aiohttp.ClientSession(
                connector=self._conn(), timeout=aiohttp.ClientTimeout(total=3)
            ) as s:
                async with s.get(f"{self.ollama_base_url}/api/tags") as r:
                    if r.status != 200:
                        return {"reachable": False, "models": []}
                    data = await r.json()
            models = [m.get("name") for m in (data.get("models") or []) if m.get("name")]
            return {"reachable": True, "models": models}
        except Exception:
            return {"reachable": False, "models": []}

    # ---- provider resolution ---------------------------------------------
    async def resolve(self) -> Dict[str, Any]:
        """Return {provider, model, available, providers} describing the active choice."""
        oll = await self.ollama_status()
        avail = {"ollama": oll["reachable"]}
        for p in _CLOUD:
            avail[p] = bool(self._cloud_key(p))

        def ollama_pick():
            if oll["reachable"]:
                m = self.ollama_model or (oll["models"][0] if oll["models"] else None)
                if m:
                    return ("ollama", m)
            return (None, None)

        provider = model = None
        if self.provider == "ollama":
            provider, model = ollama_pick()
        elif self.provider in _CLOUD:
            if self._cloud_key(self.provider):
                provider, model = self.provider, self._cloud_model(self.provider)
        else:  # auto
            provider, model = ollama_pick()
            if not provider:
                for cp in _CLOUD:
                    if self._cloud_key(cp):
                        provider, model = cp, self._cloud_model(cp)
                        break

        return {"provider": provider, "model": model,
                "available": provider is not None, "providers": avail,
                "configured": self.provider}

    # ---- completion -------------------------------------------------------
    async def complete(self, prompt: str, system: Optional[str] = None) -> str:
        r = await self.resolve()
        provider, model = r["provider"], r["model"]
        if not provider:
            raise LLMError("no LLM provider available; start Ollama with a model, "
                           "or set a cloud API key (ANTHROPIC_API_KEY / OPENAI_API_KEY / DEEPSEEK_API_KEY)")
        if provider == "ollama":
            return await self._ollama(model, prompt, system)
        return await self._cloud(provider, model, prompt, system)

    async def _ollama(self, model: str, prompt: str, system: Optional[str]) -> str:
        body: Dict[str, Any] = {"model": model, "prompt": prompt, "stream": False,
                                "options": {"temperature": 0.2, "num_predict": self.max_tokens}}
        if system:
            body["system"] = system
        async with aiohttp.ClientSession(
            connector=self._conn(),
            timeout=aiohttp.ClientTimeout(connect=5, total=170)
        ) as s:
            async with s.post(f"{self.ollama_base_url}/api/generate", json=body) as r:
                if r.status != 200:
                    raise LLMError(f"ollama HTTP {r.status}")
                d = await r.json()
        return (d.get("response") or "").strip()

    async def _cloud(self, provider: str, model: str, prompt: str, system: Optional[str]) -> str:
        key = self._cloud_key(provider)
        if not key:
            raise LLMError(f"{provider}: API key not set")
        async with aiohttp.ClientSession(
            connector=self._conn(), timeout=aiohttp.ClientTimeout(total=60)
        ) as s:
            if provider == "anthropic":
                headers = {"x-api-key": key, "anthropic-version": "2023-06-01",
                           "content-type": "application/json"}
                # NB: current Claude models 400 on `temperature`, so omit it.
                body: Dict[str, Any] = {"model": model, "max_tokens": self.max_tokens,
                                        "messages": [{"role": "user", "content": prompt}]}
                if system:
                    body["system"] = system
                url = "https://api.anthropic.com/v1/messages"
                async with s.post(url, headers=headers, json=body) as r:
                    if r.status != 200:
                        raise LLMError(f"anthropic HTTP {r.status}: {(await r.text())[:200]}")
                    d = await r.json()
                parts = [b.get("text", "") for b in d.get("content", []) if b.get("type") == "text"]
                return "".join(parts).strip()
            # openai + deepseek share the OpenAI chat-completions shape
            base = "https://api.openai.com/v1" if provider == "openai" else "https://api.deepseek.com"
            msgs = [{"role": "user", "content": prompt}]
            if system:
                msgs = [{"role": "system", "content": system}] + msgs
            headers = {"authorization": f"Bearer {key}", "content-type": "application/json"}
            body = {"model": model, "messages": msgs, "max_tokens": self.max_tokens}
            async with s.post(f"{base}/chat/completions", headers=headers, json=body) as r:
                if r.status != 200:
                    raise LLMError(f"{provider} HTTP {r.status}: {(await r.text())[:200]}")
                d = await r.json()
            choices = d.get("choices") or []
            return ((choices[0].get("message", {}).get("content") if choices else "") or "").strip()

    # ---- feature: event brief --------------------------------------------
    async def summarize_event(self, ev: Dict[str, Any]) -> str:
        meta = ev.get("meta") or {}
        lines = [f"Source: {ev.get('source')}", f"Title: {ev.get('title')}"]
        if ev.get("summary"):
            lines.append(f"Summary: {ev['summary']}")
        for k in ("cve", "vendor", "product", "group_name", "country_display",
                  "activity", "malware", "ioc", "ioc_type"):
            if meta.get(k):
                lines.append(f"{k}: {meta[k]}")
        system = ("You are a senior SOC analyst. Explain this threat-intel event in 2-4 short "
                  "sentences: what it is, why it matters, and the single most useful action a "
                  "blue team should take. Write plain prose only, no Markdown, no bold or "
                  "asterisks, no headings, no bullet or numbered lists. Be specific, no filler.")
        return await self.complete("\n".join(lines), system=system)
