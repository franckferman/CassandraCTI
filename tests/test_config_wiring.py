"""Config wiring tests: connector `use`, inline transports, nested ${ENV}
expansion via _walk, missing connectors file, and schema validation.
"""
import pytest
from pydantic import ValidationError

from cassandra_cti.config import load_settings
from cassandra_cti.config_schema import SettingsModel


def test_use_connector_is_loaded_with_env_expanded_params(tmp_path, monkeypatch):
    monkeypatch.setenv("MY_HOOK", "https://hooks.example/abc")
    connectors = tmp_path / "connectors.yaml"
    connectors.write_text(
        """
connectors:
  - id: slackbot
    type: slack
    params:
      webhook_url: ${MY_HOOK}
"""
    )
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        """
transports:
  use: [slackbot]
"""
    )
    settings = load_settings(str(cfg), connectors_path=str(connectors))
    by_id = {t.id: t for t in settings.transports}
    assert "slackbot" in by_id
    t = by_id["slackbot"]
    assert t.type == "slack"
    # ${MY_HOOK} was expanded from the environment.
    assert t.params["webhook_url"] == "https://hooks.example/abc"


def test_inline_transport_pops_id_and_sets_type(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        """
transports:
  teams:
    - id: team1
      webhook_url: https://teams.example/hook
"""
    )
    settings = load_settings(str(cfg))
    teams = [t for t in settings.transports if t.type == "teams"]
    assert len(teams) == 1
    t = teams[0]
    assert t.id == "team1"
    # id is popped out of params, the rest stays.
    assert "id" not in t.params
    assert t.params["webhook_url"] == "https://teams.example/hook"


def test_nested_env_expansion_missing_var_left_literal(tmp_path, monkeypatch):
    monkeypatch.setenv("KNOWN", "hello")
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        """
transports:
  teams:
    - id: t1
      webhook_url: ${KNOWN}/${MISSING}
routes:
  - name: r1
    include_regex: ${KNOWN}-${MISSING}
    transports: [t1]
"""
    )
    settings = load_settings(str(cfg))
    # Transport param: known var expanded, missing var kept literal.
    t = [x for x in settings.transports if x.type == "teams"][0]
    assert t.params["webhook_url"] == "hello/${MISSING}"
    # Route field is expanded by _walk with the same missing-var behaviour.
    r = settings.routes[0]
    assert r.include_regex == "hello-${MISSING}"


def test_missing_connectors_file_does_not_crash(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        """
transports:
  use: [nope]
"""
    )
    missing = str(tmp_path / "does_not_exist.yaml")
    settings = load_settings(str(cfg), connectors_path=missing)
    # No connectors resolved, but nothing raised.
    assert settings.transports == []


def test_settings_model_rejects_route_without_name():
    with pytest.raises(ValidationError):
        SettingsModel(routes=[{"transports": ["t1"]}])
