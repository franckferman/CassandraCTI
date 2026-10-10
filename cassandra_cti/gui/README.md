# GUI (optional)

A thin PySide6 desktop wrapper around the `cassandra` CLI. Opt-in, and the CLI
works with zero GUI dependency.

```bash
pip install 'CassandraCTI[gui]'   # adds PySide6
cassandra-gui                     # or: python -m cassandra_cti.gui
```

Pick a subcommand on the left, fill the form, press Run (Ctrl+G). The command
it will execute is shown above the output; stdout lands in Output, the command
line and stderr in Log.

## Invariants

These are deliberate. Keep them.

- **Subprocess only.** The GUI reaches the pipeline exclusively by running the
  CLI (`runner.py`). It never does `from cassandra_cti.core import ...` or
  imports `cli`. The CLI is the single source of truth; change a flag and only
  `forms.py` changes here.
- **`runner.py` and `forms.py` are Qt-free.** `runner.py` is pure stdlib,
  `forms.py` is pure data. Both import without a display and without PySide6,
  which is why the tests need neither.
- **Resilient CLI resolution.** `resolve_cli_bin()` tries the sibling of the
  running interpreter, then PATH, then `python -m cassandra_cti`. The module
  fallback is the safety net for a launch without an active venv (a bare PATH
  would give rc=127); it needs `cassandra_cti/__main__.py`.
- **PySide6 is an extra.** Importing `app` without it is safe (no traceback);
  `main()` prints an install hint and exits 1.

## Why PySide6

Official Qt for Python binding, LGPL, future-proof. Not PyQt (third-party,
GPL), not tkinter (dated, awkward for a dashboard layout).

## Tests

`tests/test_gui_runner.py` (alongside the rest of the suite) covers the runner
and the form schema with no Qt and no real `cassandra` binary (the CLI is faked
with a `python -c` prefix). Widget behaviour is not unit-tested; the runner
tests plus the CLI's own suite carry the coverage.
