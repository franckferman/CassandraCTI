# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# gui/tests/test_runner.py
#
# Pure runner + forms tests. No Qt, no PySide6, no real cassandra binary:
# the CLI is faked with a `python -c` prefix.
from __future__ import annotations

import shutil
import sys

from cassandra_cti.gui import forms
from cassandra_cti.gui.runner import (
    BIN, PKG, RC_NOT_FOUND, RC_TIMEOUT, build_cmd, resolve_cli_bin, run_cli,
)

PY = sys.executable


# --- build_cmd --------------------------------------------------------------

def test_build_cmd_skips_none_and_empty_options():
    cmd = build_cmd("run", options={"interval": 300, "sources": "", "since": None}, prefix=["cli"])
    assert cmd == ["cli", "run", "--interval", "300"]


def test_build_cmd_appends_flags_verbatim():
    cmd = build_cmd("run", flags=["loop", "--verbose"], prefix=["cli"])
    assert cmd == ["cli", "run", "--loop", "--verbose"]


def test_build_cmd_keeps_positional_order_and_skips_empty():
    cmd = build_cmd("doctor", positional=["config", ""], prefix=["cli"])
    assert cmd == ["cli", "doctor", "config"]


def test_build_cmd_long_option_name_passed_through():
    cmd = build_cmd("x", options={"--already-dashed": "v"}, prefix=["cli"])
    assert cmd == ["cli", "x", "--already-dashed", "v"]


def test_build_cmd_uses_resolver_when_no_prefix():
    cmd = build_cmd("list")
    assert cmd[-1] == "list"
    assert len(cmd) >= 2


# --- resolve_cli_bin --------------------------------------------------------

def test_resolve_prefers_sibling_of_interpreter(tmp_path, monkeypatch):
    fake_py = tmp_path / "python"
    fake_py.write_text("")
    (tmp_path / BIN).write_text("")
    monkeypatch.setattr(sys, "executable", str(fake_py))
    assert resolve_cli_bin() == [str(tmp_path / BIN)]


def test_resolve_falls_back_to_path(tmp_path, monkeypatch):
    fake_py = tmp_path / "python"
    fake_py.write_text("")
    monkeypatch.setattr(sys, "executable", str(fake_py))
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/cassandra")
    assert resolve_cli_bin() == ["/usr/bin/cassandra"]


def test_resolve_last_resort_is_module(tmp_path, monkeypatch):
    fake_py = tmp_path / "python"
    fake_py.write_text("")
    monkeypatch.setattr(sys, "executable", str(fake_py))
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert resolve_cli_bin() == [str(fake_py), "-m", PKG]


# --- run_cli ----------------------------------------------------------------

def test_run_cli_captures_stdout_and_zero_rc():
    r = run_cli("x", prefix=[PY, "-c", "print('hello')"])
    assert r.returncode == 0 and r.ok
    assert "hello" in r.stdout


def test_run_cli_propagates_nonzero_rc():
    r = run_cli("x", prefix=[PY, "-c", "import sys; sys.exit(3)"])
    assert r.returncode == 3 and not r.ok


def test_run_cli_captures_stderr():
    r = run_cli("x", prefix=[PY, "-c", "import sys; sys.stderr.write('boom')"])
    assert "boom" in r.stderr


def test_run_cli_timeout_returns_124():
    r = run_cli("x", prefix=[PY, "-c", "import time; time.sleep(5)"], timeout=0.3)
    assert r.returncode == RC_TIMEOUT


def test_run_cli_missing_binary_returns_127():
    r = run_cli("x", prefix=["cassandra-does-not-exist-zzz"])
    assert r.returncode == RC_NOT_FOUND
    assert "not found" in r.stderr


def test_run_cli_lists_files_created_in_out_dir(tmp_path):
    script = "import pathlib, sys; (pathlib.Path(sys.argv[2]) / 'made.txt').write_text('x')"
    r = run_cli("gen", positional=[str(tmp_path)], prefix=[PY, "-c", script], out_dir=str(tmp_path))
    assert r.returncode == 0
    assert any(p.endswith("made.txt") for p in r.output_paths)


def test_run_cli_records_the_command():
    r = run_cli("x", prefix=[PY, "-c", "pass"])
    assert r.cmd[0] == PY and r.cmd[-1] == "x"


# --- forms ------------------------------------------------------------------

def test_forms_cover_their_subcommands():
    assert set(forms.subcommands()) == set(forms.FORMS.keys())
    assert len(forms.FORMS) >= 10


def test_every_field_kind_is_known():
    known = {"line", "text", "spin", "combo", "check"}
    for form in forms.FORMS.values():
        for fld in form.positional + form.options:
            assert fld.kind in known, (form.subcmd, fld.name, fld.kind)


def test_subcmd_names_match_keys():
    for name, form in forms.FORMS.items():
        assert form.subcmd == name


def test_positionals_are_flagged_and_unnamed():
    for form in forms.FORMS.values():
        for fld in form.positional:
            assert fld.is_positional and fld.name == ""


def test_spin_fields_carry_a_range():
    for form in forms.FORMS.values():
        for fld in form.positional + form.options:
            if fld.kind == "spin":
                assert len(fld.choices) == 2 and fld.choices[0] <= fld.choices[1]
