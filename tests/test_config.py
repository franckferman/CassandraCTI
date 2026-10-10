import os

import pytest
from pydantic import ValidationError

from cassandra_cti.config import load_settings
from cassandra_cti.config_schema import SettingsModel

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_shipped_example_config_is_valid():
    settings = load_settings(os.path.join(ROOT, "config.example.yaml"))
    assert settings.routes
    assert any(r.name == "ransomware" for r in settings.routes)


def test_route_without_name_is_rejected():
    with pytest.raises(ValidationError):
        SettingsModel(routes=[{"transports": ["t1"]}])


def test_inventory_and_llm_are_schema_modelled():
    # main.py / the web dashboard consume settings.inventory and settings.llm,
    # so the schema must model them (otherwise `doctor config` silently drops
    # the sections instead of validating them).
    m = SettingsModel(inventory={"enabled": True, "terms": ["Fortinet"]},
                      llm={"enabled": True, "provider": "auto"})
    assert m.inventory["terms"] == ["Fortinet"]
    assert m.llm["provider"] == "auto"


def test_load_settings_preserves_inventory_and_llm(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text(
        "schema_version: 1\n"
        "inventory:\n  enabled: true\n  terms: ['Cisco']\n"
        "llm:\n  enabled: true\n  provider: ollama\n", encoding="utf-8")
    s = load_settings(str(p))
    assert s.inventory["terms"] == ["Cisco"]
    assert s.llm["provider"] == "ollama"
