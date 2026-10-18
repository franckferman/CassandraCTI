# GUI (optional)

A PySide6 desktop console for CassandraCTI. Opt-in, and the CLI works with zero
GUI dependency.

```bash
pip install 'CassandraCTI[gui]'   # adds PySide6
cassandra gui                     # or: cassandra-gui, or: python -m cassandra_cti.gui
```

It is a task-oriented front end over the CLI, themed to match the project's
site (near-black, amber accent, monospace for anything machine-written):

- **Dashboard** counts what is configured and runs the pipeline in a click.
- **Sources / Connectors / Routes / Briefings** show the current config in a
  table and edit it (add, remove, test a connector, run a briefing) through the
  CLI's own verbs.
- **Run** streams a live pipeline run, with Stop.
- **Config files** edits config.yaml and connectors.yaml directly (comments are
  kept) and validates with `doctor config`.
- **Settings** sets the workspace location once and edits the LLM layer
  (provider, model, Ollama endpoint, token budget).

## Invariants

These are deliberate. Keep them.

- **Never import the core.** The GUI reaches the pipeline only by running the
  CLI (`runner.py`), and only ever reads or writes the config *files*
  (`state.py` reads, `confio.py` writes). It never does
  `from cassandra_cti.core import ...` or imports `cli`. The CLI is the single
  source of truth for actions; change a flag and only `forms.py` changes here.
- **The non-Qt layers are non-Qt.** `runner.py` (pure stdlib), `forms.py` (pure
  data), `state.py` (stdlib + PyYAML), `confio.py` (stdlib + ruamel) and
  `theme.py` (pure strings) carry no Qt import, import without a display, and
  are what the tests exercise. Only `app.py` touches PySide6.
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

`tests/test_gui_runner.py` covers the runner and the form schema;
`tests/test_gui_state.py` covers the workspace reader, the theme string and the
config writer. All of it runs with no Qt, no display and no real `cassandra`
binary (the CLI is faked with a `python -c` prefix). The widgets in `app.py`
are not unit-tested; the layers below them plus the CLI's own suite carry the
coverage.
