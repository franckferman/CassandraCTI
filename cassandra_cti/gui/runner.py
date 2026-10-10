# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# gui/runner.py
#
# Subprocess bridge to the cassandra CLI. Pure stdlib: no Qt, no core import.
# Testable without a display and without PySide6.
from __future__ import annotations

import shutil
import subprocess  # nosec B404 - we run a built argv list, never a shell string
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

PKG = "cassandra_cti"
BIN = "cassandra"

RC_TIMEOUT = 124
RC_NOT_FOUND = 127


@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str
    cmd: list[str]
    output_paths: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def resolve_cli_bin() -> list[str]:
    # Order matters. Never trust the parent PATH alone: a GUI launched from a
    # .desktop file or without an active venv would get rc=127. The module
    # fallback always works as long as the package is importable.
    sibling = Path(sys.executable).resolve().with_name(BIN)
    if sibling.exists():
        return [str(sibling)]
    on_path = shutil.which(BIN)
    if on_path:
        return [on_path]
    return [sys.executable, "-m", PKG]


def build_cmd(
    subcmd: str,
    positional: Optional[list] = None,
    options: Optional[dict] = None,
    flags: Optional[list] = None,
    prefix: Optional[list] = None,
) -> list[str]:
    # prefix overrides the resolved binary (handy for tests). options with a
    # None or empty value are skipped. flags are appended verbatim.
    cmd = list(prefix) if prefix is not None else resolve_cli_bin()
    cmd.append(subcmd)
    for value in positional or []:
        if value not in (None, ""):
            cmd.append(str(value))
    for name, value in (options or {}).items():
        if value in (None, ""):
            continue
        cmd.append(name if name.startswith("-") else f"--{name}")
        cmd.append(str(value))
    for flag in flags or []:
        cmd.append(flag if flag.startswith("-") else f"--{flag}")
    return cmd


def run_cli(
    subcmd: str,
    positional: Optional[list] = None,
    options: Optional[dict] = None,
    flags: Optional[list] = None,
    prefix: Optional[list] = None,
    timeout: float = 30,
    out_dir: Optional[str] = None,
) -> RunResult:
    # out_dir, when given, is scanned for files created by the run and listed in
    # output_paths. The CLI is not forced to write there (its subcommands have
    # no generic --out); callers that know a command writes files point it here.
    cmd = build_cmd(subcmd, positional, options, flags, prefix)

    track = out_dir if out_dir is not None else tempfile.mkdtemp(prefix="cassandra-gui-")
    before: set[str] = set()
    try:
        before = {str(p) for p in Path(track).rglob("*")}
    except OSError:
        pass

    try:
        proc = subprocess.run(  # nosec B603 - cmd is a list (shell=False), not untrusted shell input
            cmd, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        err = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        return RunResult(RC_TIMEOUT, "", err + f"timed out after {timeout}s", cmd, [])
    except FileNotFoundError as exc:
        return RunResult(RC_NOT_FOUND, "", f"cli not found: {exc}", cmd, [])

    produced: list[str] = []
    try:
        produced = sorted(
            str(p) for p in Path(track).rglob("*")
            if p.is_file() and str(p) not in before
        )
    except OSError:
        pass

    return RunResult(proc.returncode, proc.stdout, proc.stderr, cmd, produced)
