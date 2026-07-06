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
