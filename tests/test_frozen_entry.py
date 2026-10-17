# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# tests/test_frozen_entry.py
#
# The frozen single-exe dispatch and the runner's frozen branch. No Qt, no
# subprocess: we monkeypatch the two faces and assert routing only.
import sys

import cassandra_cti.frozen_entry as fe
from cassandra_cti.gui import runner


def test_sentinel_routes_to_cli(monkeypatch):
    called = {}
    monkeypatch.setattr(fe, "_run_cli", lambda: called.setdefault("cli", True))

    def fake_gui():
        called["gui"] = True
        return 0

    monkeypatch.setattr(fe, "_run_gui", fake_gui)
    monkeypatch.setattr(sys, "argv", ["cassandra", runner.FROZEN_CLI_ARG, "run", "--help"])
    assert fe.main() == 0
    assert called == {"cli": True}
    # The sentinel is stripped so Typer sees a normal argv.
    assert sys.argv == ["cassandra", "run", "--help"]


def test_no_sentinel_routes_to_gui(monkeypatch):
    called = {}
    monkeypatch.setattr(fe, "_run_cli", lambda: called.setdefault("cli", True))

    def fake_gui():
        called["gui"] = True
        return 7

    monkeypatch.setattr(fe, "_run_gui", fake_gui)
    monkeypatch.setattr(sys, "argv", ["cassandra"])
    assert fe.main() == 7
    assert called == {"gui": True}


def test_runner_frozen_branch(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", "/opt/cassandra/cassandra")
    assert runner.resolve_cli_bin() == ["/opt/cassandra/cassandra", runner.FROZEN_CLI_ARG]


def test_runner_not_frozen_never_uses_sentinel(monkeypatch):
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    assert runner.FROZEN_CLI_ARG not in runner.resolve_cli_bin()


def test_selftest_reports_diagnostics(monkeypatch, capsys):
    import json
    monkeypatch.setattr(sys, "argv", ["cassandra", fe.SELFTEST_ARG])
    assert fe.main() == 0
    out = json.loads(capsys.readouterr().out)
    assert out["sentinel"] == runner.FROZEN_CLI_ARG
    assert out["frozen"] is False  # pytest is not a frozen build
    assert isinstance(out["cli_bridge_cmd"], list) and out["cli_bridge_cmd"]
