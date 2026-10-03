"""Tests for `cassandra service ...` (unit generation + install flow, offline).

No real systemctl / rc-service is ever invoked: enable/status calls are
monkeypatched and file writes are redirected under tmp_path (HOME override for
systemd --user, openrc_path override for OpenRC)."""
import os
import stat

import pytest
from typer.testing import CliRunner

from cassandra_cti import service as svc
from cassandra_cti.cli import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def _fake_default_dir(monkeypatch, tmp_path):
    monkeypatch.setattr("cassandra_cti.cli.default_dir", lambda: tmp_path / "appdir")


# --------------------------------------------------------------------------- #
# Pure renderers / helpers
# --------------------------------------------------------------------------- #
def test_render_systemd_system():
    u = svc.render_systemd_unit(exec_cmd="/usr/bin/cassandra run --loop", user_mode=False)
    assert "ExecStart=/usr/bin/cassandra run --loop" in u
    assert "Restart=always" in u and "RestartSec=10" in u
    assert "WantedBy=multi-user.target" in u
    assert "EnvironmentFile" not in u


def test_render_systemd_user_with_envfile():
    u = svc.render_systemd_unit(exec_cmd="/x/cassandra run", user_mode=True,
                                env_file="/etc/cassandra.env")
    assert "WantedBy=default.target" in u
    assert "EnvironmentFile=/etc/cassandra.env" in u


def test_render_openrc():
    s = svc.render_openrc_script(exec_path="/usr/bin/cassandra",
                                 run_args_full="run --loop --interval 300")
    assert s.startswith("#!/sbin/openrc-run")
    assert 'command="/usr/bin/cassandra"' in s
    assert 'command_args="run --loop --interval 300"' in s
    assert "supervisor=supervise-daemon" in s and "respawn_max=0" in s


def test_build_run_args_appends_paths():
    a = svc.build_run_args("run --loop", "/c/config.yaml", "/c/connectors.yaml")
    assert a == "run --loop --config /c/config.yaml --connectors /c/connectors.yaml"


def test_build_run_args_respects_explicit_config():
    a = svc.build_run_args("run --config /my/c.yaml", "/c/config.yaml", "/c/connectors.yaml")
    assert a.count("--config") == 1 and "/my/c.yaml" in a
    assert "--connectors /c/connectors.yaml" in a


def test_detect_init_prefers_systemd(monkeypatch):
    monkeypatch.setattr(svc.os.path, "isdir", lambda p: p == "/run/systemd/system")
    assert svc.detect_init() == "systemd"


def test_detect_init_openrc(monkeypatch):
    monkeypatch.setattr(svc.os.path, "isdir", lambda p: False)
    monkeypatch.setattr(svc.shutil, "which",
                        lambda n: "/sbin/rc-service" if n == "rc-service" else None)
    assert svc.detect_init() == "openrc"


def test_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert svc.systemd_path("cti", user_mode=False) == svc.SYSTEMD_SYSTEM_DIR / "cti.service"
    assert str(svc.systemd_path("cti", user_mode=True)).endswith(".config/systemd/user/cti.service")
    assert svc.openrc_path("cti") == svc.OPENRC_DIR / "cti"


# --------------------------------------------------------------------------- #
# CLI flow
# --------------------------------------------------------------------------- #
def test_install_show_writes_nothing(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    r = runner.invoke(app, ["service", "install", "--init", "systemd", "--user", "--show"])
    assert r.exit_code == 0
    assert "[Service]" in r.stdout and "ExecStart=" in r.stdout
    assert not (tmp_path / ".config" / "systemd" / "user").exists()


def test_install_systemd_user_writes_unit(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    r = runner.invoke(app, ["service", "install", "--init", "systemd", "--user",
                            "--no-enable", "--command", "run --loop --since 2026-08-14"])
    assert r.exit_code == 0, r.output
    unit = tmp_path / ".config" / "systemd" / "user" / "cassandra-cti.service"
    assert unit.exists()
    txt = unit.read_text()
    assert "run --loop --since 2026-08-14" in txt
    assert "--config" in txt and "--connectors" in txt


def test_install_enable_success_path(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    seen = {}

    def fake_enable(init, name, user_mode):
        seen["init"] = init
        return True
    monkeypatch.setattr(svc, "enable_service", fake_enable)
    r = runner.invoke(app, ["service", "install", "--init", "systemd", "--user"])
    assert r.exit_code == 0
    assert seen.get("init") == "systemd"
    assert "enabled and started" in r.stdout


def test_install_openrc_rejects_user():
    r = runner.invoke(app, ["service", "install", "--init", "openrc", "--user", "--show"])
    assert r.exit_code != 0
    assert "per-user" in r.output


def test_install_openrc_writes_and_chmods(monkeypatch, tmp_path):
    target = tmp_path / "init.d" / "cassandra-cti"
    monkeypatch.setattr(svc, "openrc_path", lambda name: target)
    monkeypatch.setattr(svc, "enable_service", lambda *a, **k: True)
    r = runner.invoke(app, ["service", "install", "--init", "openrc"])
    assert r.exit_code == 0, r.output
    assert target.exists()
    assert target.read_text().startswith("#!/sbin/openrc-run")
    assert os.stat(target).st_mode & stat.S_IXUSR


def test_install_bad_init():
    r = runner.invoke(app, ["service", "install", "--init", "upstart", "--show"])
    assert r.exit_code != 0
    assert "init system" in r.output
