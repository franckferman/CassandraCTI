# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# frozen_entry.py
#
# Single entry point for the frozen (PyInstaller) build. One executable ships
# both faces of the app: double-clicked it opens the desktop GUI; re-invoked
# with the sentinel first argument it runs the Typer CLI instead. The GUI's
# subprocess bridge (gui/runner.py) uses that sentinel to reach the CLI inside
# the bundle, where "python -m cassandra_cti" is not available. Importing Qt
# and importing core stay on separate branches, so a single process never
# loads both.
from __future__ import annotations

import sys

from cassandra_cti.gui.runner import FROZEN_CLI_ARG

# Prints frozen-build diagnostics and exits. CI runs it against every bundle to
# confirm the build is frozen and the GUI->CLI bridge resolves to this exe.
SELFTEST_ARG = "__selftest__"


def _run_cli() -> None:
    from cassandra_cti.cli import app
    app()


def _run_gui() -> int:
    from cassandra_cti.gui.app import main as gui_main
    return gui_main()


def _selftest() -> int:
    import json

    from cassandra_cti.gui import runner

    print(json.dumps({
        "frozen": bool(getattr(sys, "frozen", False)),
        "executable": sys.executable,
        "cli_bridge_cmd": runner.resolve_cli_bin(),
        "sentinel": runner.FROZEN_CLI_ARG,
    }))
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == SELFTEST_ARG:
        return _selftest()
    if len(sys.argv) > 1 and sys.argv[1] == FROZEN_CLI_ARG:
        # CLI face: drop the sentinel so Typer sees a normal argv, then run.
        del sys.argv[1]
        _run_cli()
        return 0
    # GUI face (default): the double-click entry point.
    return _run_gui()


if __name__ == "__main__":
    sys.exit(main())
