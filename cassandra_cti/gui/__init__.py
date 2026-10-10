# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# gui/__init__.py
#
# Optional PySide6 wrapper around the cassandra CLI.
#
# Invariants (do not break):
#   - This package talks to the CLI only through subprocess (runner.py).
#     It never imports cassandra_cti.core/cli/*. The CLI is the single source
#     of truth; a flag change touches only forms.py here.
#   - runner.py and forms.py are pure stdlib / pure data: no Qt import, so they
#     test without a display and without PySide6 installed.
#   - PySide6 is an opt-in extra (`pip install CassandraCTI[gui]`); the CLI
#     stays usable with zero GUI dependency.
