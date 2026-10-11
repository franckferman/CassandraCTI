# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# gui/app.py
#
# The desktop app: a themed, task-oriented front end over the cassandra CLI. It
# shows what is configured (read from config.yaml / connectors.yaml via
# state.py), edits it through the CLI's own verbs, streams a live run, and lets
# you edit the config files and the LLM layer. It never imports the core: every
# action is a CLI call (runner.py) or a direct edit of the config files
# (confio.py). Qt is an optional extra; importing this module without it is safe.
from __future__ import annotations

import sys
from pathlib import Path

from . import confio, forms, runner, state, theme

try:
    from PySide6.QtCore import Qt, QProcess, QSettings
    from PySide6.QtGui import QAction, QKeySequence
    from PySide6.QtWidgets import (
        QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
        QFileDialog, QFormLayout, QFrame, QGridLayout, QHBoxLayout, QHeaderView,
        QLabel, QLineEdit, QListWidget, QMainWindow, QMessageBox, QPlainTextEdit,
        QPushButton, QSpinBox, QStackedWidget, QTabWidget, QTableWidget,
        QTableWidgetItem, QToolBar, QVBoxLayout, QWidget,
    )
    _HAVE_QT = True
except ImportError:
    _HAVE_QT = False


_INSTALL_HINT = "PySide6 is not installed. Install the GUI extra with:\n    pip install 'CassandraCTI[gui]'\n"

# Which path flags each subcommand accepts: (accepts --config, --connectors).
# The window injects the workspace paths so no form ever asks for them.
PATH_FLAGS = {
    "init": (True, True),
    "run": (True, True),
    "doctor": (True, True),
    "list": (True, True),
    "add-source": (True, False),
    "remove-source": (True, False),
    "import-feeds": (True, False),
    "add-connector": (False, True),
    "remove-connector": (True, True),
    "routes-add": (True, False),
    "routes-remove": (True, False),
    "channel-add": (True, True),
    "briefing-add": (True, False),
    "briefing-remove": (True, False),
    "briefing-run": (True, True),
    "backfill": (True, True),
}

NAV = ["Dashboard", "Sources", "Connectors", "Routes", "Briefings", "Run", "Config files", "Settings"]

PROVIDERS = ("auto", "ollama", "anthropic", "openai", "deepseek")


if _HAVE_QT:

    # (display label, stored value). "system" follows the OS color scheme.
    THEME_CHOICES = (("System (OS)", "system"), ("Dark", "dark"), ("Light", "light"))

    def _resolve_mode(pref: str) -> str:
        # Turn a preference into a concrete 'dark' or 'light'. "system" asks Qt
        # for the OS color scheme (Qt 6.5+); dark is the fallback.
        if pref in ("dark", "light"):
            return pref
        app = QApplication.instance()
        try:
            if app is not None and app.styleHints().colorScheme() == Qt.ColorScheme.Light:
                return "light"
        except (AttributeError, TypeError):
            pass
        return "dark"

    def apply_theme(pref: str) -> None:
        app = QApplication.instance()
        if app is not None:
            app.setStyleSheet(theme.stylesheet(_resolve_mode(pref)))

    def _divider() -> QFrame:
        line = QFrame()
        line.setObjectName("divider")
        return line

    def _label(text: str, obj: str = "") -> QLabel:
        lab = QLabel(text)
        if obj:
            lab.setObjectName(obj)
        return lab

    def _widget_for(fld: forms.Field):
        # One widget per field kind. Returns (widget, getter) where getter()
        # yields the current value as a plain python object.
        if fld.kind == "line":
            w = QLineEdit()
            w.setText(str(fld.default or ""))
            return w, w.text
        if fld.kind == "text":
            w = QPlainTextEdit()
            w.setPlainText(str(fld.default or ""))
            w.setFixedHeight(70)
            return w, w.toPlainText
        if fld.kind == "spin":
            w = QSpinBox()
            lo, hi = (fld.choices or (0, 1000))
            w.setRange(int(lo), int(hi))
            w.setValue(int(fld.default or 0))
            return w, w.value
        if fld.kind == "combo":
            w = QComboBox()
            w.addItems([str(c) for c in fld.choices])
            if fld.default:
                w.setCurrentText(str(fld.default))
            return w, w.currentText
        if fld.kind == "check":
            w = QCheckBox()
            w.setChecked(bool(fld.default))
            return w, w.isChecked
        raise ValueError(f"unknown field kind: {fld.kind}")

    class FormDialog(QDialog):
        # A modal form for one CLI verb, built from forms.FORMS. The config and
        # connectors path fields are dropped: the window injects them.
        def __init__(self, form: forms.Form, title: str, parent=None):
            super().__init__(parent)
            self.setWindowTitle(title)
            self.setMinimumWidth(460)
            self.form = form
            self._fields = []

            root = QVBoxLayout(self)
            root.addWidget(_label(form.description, "pageHint"))
            grid = QFormLayout()
            grid.setLabelAlignment(Qt.AlignRight)
            for fld in list(form.positional) + list(form.options):
                if fld.name in ("config", "connectors"):
                    continue
                w, getter = _widget_for(fld)
                if fld.help:
                    w.setToolTip(fld.help)
                grid.addRow(fld.label, w)
                self._fields.append((fld, getter))
            root.addLayout(grid)

            buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            buttons.accepted.connect(self.accept)
            buttons.rejected.connect(self.reject)
            root.addWidget(buttons)

        def collect(self):
            positional, options, flags = [], {}, []
            for fld, getter in self._fields:
                value = getter()
                if fld.is_positional:
                    positional.append(value)
                elif fld.kind == "check":
                    if value != fld.default:
                        flags.append(fld.name if value else f"no-{fld.name}")
                else:
                    options[fld.name] = value
            return positional, options, flags

    class Page(QWidget):
        # Base page: a title, a hint, and a refresh() the window calls on show.
        def __init__(self, win, title: str, hint: str):
            super().__init__()
            self.win = win
            self.root = QVBoxLayout(self)
            self.root.setContentsMargins(22, 18, 22, 18)
            self.root.setSpacing(10)
            self.root.addWidget(_label(title, "pageTitle"))
            self.root.addWidget(_label(hint, "pageHint"))

        def refresh(self):
            pass

    class StatCard(QFrame):
        def __init__(self, label: str):
            super().__init__()
            self.setObjectName("card")
            self.setFrameShape(QFrame.NoFrame)
            lay = QVBoxLayout(self)
            lay.setContentsMargins(16, 14, 16, 14)
            self.value = _label("0", "stat")
            lay.addWidget(self.value)
            lay.addWidget(_label(label, "statLabel"))

    class DashboardPage(Page):
        def __init__(self, win):
            super().__init__(win, "Dashboard", "The workspace at a glance.")
            grid = QGridLayout()
            grid.setSpacing(12)
            self.cards = {}
            for col, key in enumerate(("sources", "connectors", "routes", "briefings")):
                card = StatCard(key.upper())
                self.cards[key] = card
                grid.addWidget(card, 0, col)
            self.root.addLayout(grid)

            self.health = _label("", "healthOk")
            self.root.addWidget(self.health)
            self.root.addWidget(_divider())

            actions = QHBoxLayout()
            run_once = QPushButton("Run once")
            run_once.setObjectName("primary")
            run_once.clicked.connect(lambda: self._run(False))
            watch = QPushButton("Run and watch")
            watch.clicked.connect(lambda: self._run(True))
            health = QPushButton("Health check")
            health.clicked.connect(self._health)
            for btn in (run_once, watch, health):
                actions.addWidget(btn)
            actions.addStretch(1)
            self.root.addLayout(actions)
            self.root.addStretch(1)

        def _run(self, loop: bool):
            self.win.goto("Run")
            self.win.pages["Run"].start(loop)

        def _health(self):
            result = self.win.run_cli("doctor", ["config"], timeout=30)
            text = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
            box = QMessageBox(self)
            box.setWindowTitle("Health check: doctor config")
            box.setText(text.strip() or f"rc={result.returncode}")
            box.exec()

        def refresh(self):
            ws = self.win.ws
            self.cards["sources"].value.setText(f"{ws.enabled_sources}/{len(ws.sources)}")
            self.cards["connectors"].value.setText(str(len(ws.connectors)))
            self.cards["routes"].value.setText(str(len(ws.routes)))
            self.cards["briefings"].value.setText(str(len(ws.briefings)))
            if not ws.config_exists:
                self.health.setObjectName("healthWarn")
                self.health.setText("no config.yaml at this path yet: run 'cassandra init' once, then Reload (Ctrl+R)")
            else:
                self.health.setObjectName("healthOk")
                self.health.setText(f"config: {ws.config_path}   provider: {ws.llm.provider}" + ("  llm:on" if ws.llm.enabled else "  llm:off"))
            self.health.setStyleSheet(self.win.styleSheet())

    class TablePage(Page):
        # A state-driven list: a table, plus Add / Remove / extra action buttons.
        # loader(ws) -> list of (cells, key). add_form is a forms key (or None).
        # remover(key) -> (subcmd, positional, options) to run, or None.
        def __init__(self, win, title, hint, columns, loader,
                     add_form=None, remover=None, extras=None):
            super().__init__(win, title, hint)
            self.columns = columns
            self.loader = loader
            self.add_form = add_form
            self.remover = remover
            self.extras = extras or []
            self._keys = []

            self.table = QTableWidget(0, len(columns))
            self.table.setHorizontalHeaderLabels(columns)
            self.table.verticalHeader().setVisible(False)
            self.table.setSelectionBehavior(QTableWidget.SelectRows)
            self.table.setSelectionMode(QTableWidget.SingleSelection)
            self.table.setEditTriggers(QTableWidget.NoEditTriggers)
            self.table.horizontalHeader().setStretchLastSection(True)
            self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
            self.root.addWidget(self.table)

            bar = QHBoxLayout()
            if add_form:
                add = QPushButton("Add")
                add.setObjectName("primary")
                add.clicked.connect(self._add)
                bar.addWidget(add)
            for label, handler in self.extras:
                btn = QPushButton(label)
                btn.clicked.connect(lambda _=False, h=handler: self._extra(h))
                bar.addWidget(btn)
            if remover:
                rem = QPushButton("Remove")
                rem.setObjectName("danger")
                rem.clicked.connect(self._remove)
                bar.addWidget(rem)
            bar.addStretch(1)
            self.root.addLayout(bar)

        def _selected_key(self):
            row = self.table.currentRow()
            if row < 0 or row >= len(self._keys):
                return None
            return self._keys[row]

        def _add(self):
            dlg = FormDialog(forms.FORMS[self.add_form], f"Add: {self.add_form}", self)
            if dlg.exec() != QDialog.Accepted:
                return
            positional, options, flags = dlg.collect()
            result = self.win.run_cli(self.add_form, positional, options, flags)
            self.win.report(result, f"Added via {self.add_form}")
            self.win.reload()

        def _remove(self):
            key = self._selected_key()
            if key is None:
                return
            spec = self.remover(key)
            if spec is None:
                return
            subcmd, positional, options = spec
            confirm = QMessageBox.question(self, "Remove", f"Remove '{key}'?")
            if confirm != QMessageBox.Yes:
                return
            result = self.win.run_cli(subcmd, positional, options)
            self.win.report(result, f"Removed {key}")
            self.win.reload()

        def _extra(self, handler):
            key = self._selected_key()
            handler(key)

        def refresh(self):
            rows = self.loader(self.win.ws)
            self._keys = [key for _, key in rows]
            self.table.setRowCount(len(rows))
            for r, (cells, _) in enumerate(rows):
                for c, text in enumerate(cells):
                    self.table.setItem(r, c, QTableWidgetItem(str(text)))

    class RunPage(Page):
        def __init__(self, win):
            super().__init__(win, "Run", "Run the pipeline once, or loop and watch it live.")
            opts = QHBoxLayout()
            self.loop = QCheckBox("loop")
            self.interval = QSpinBox()
            self.interval.setRange(5, 86400)
            self.interval.setValue(300)
            self.web = QCheckBox("web dashboard")
            self.dry = QCheckBox("dry run")
            opts.addWidget(self.loop)
            opts.addWidget(_label("every"))
            opts.addWidget(self.interval)
            opts.addWidget(_label("s"))
            opts.addWidget(self.web)
            opts.addWidget(self.dry)
            opts.addStretch(1)
            self.root.addLayout(opts)

            filt = QHBoxLayout()
            self.sources = QLineEdit()
            self.sources.setPlaceholderText("only sources (comma-separated), optional")
            self.since = QLineEdit()
            self.since.setPlaceholderText("since YYYY-MM-DD, optional")
            filt.addWidget(self.sources)
            filt.addWidget(self.since)
            self.root.addLayout(filt)

            self.console = QPlainTextEdit()
            self.console.setObjectName("console")
            self.console.setReadOnly(True)
            self.root.addWidget(self.console, 1)

            bar = QHBoxLayout()
            self.start_btn = QPushButton("Start")
            self.start_btn.setObjectName("primary")
            self.start_btn.clicked.connect(lambda: self.start(self.loop.isChecked()))
            self.stop_btn = QPushButton("Stop")
            self.stop_btn.setObjectName("danger")
            self.stop_btn.setEnabled(False)
            self.stop_btn.clicked.connect(self.stop)
            clear = QPushButton("Clear")
            clear.clicked.connect(self.console.clear)
            bar.addWidget(self.start_btn)
            bar.addWidget(self.stop_btn)
            bar.addWidget(clear)
            bar.addStretch(1)
            self.root.addLayout(bar)

            self.proc = None

        def start(self, loop: bool):
            if self.proc is not None:
                return
            cli = runner.resolve_cli_bin()
            args = cli[1:] + ["run", "--config", str(self.win.cfg_path), "--connectors", str(self.win.cx_path)]
            if loop:
                args += ["--loop", "--interval", str(self.interval.value())]
            if self.web.isChecked():
                args += ["--web"]
            if self.dry.isChecked():
                args += ["--dry-run"]
            if self.sources.text().strip():
                args += ["--sources", self.sources.text().strip()]
            if self.since.text().strip():
                args += ["--since", self.since.text().strip()]

            self.console.appendPlainText("$ " + " ".join([cli[0]] + args))
            self.proc = QProcess(self)
            self.proc.setProcessChannelMode(QProcess.MergedChannels)
            self.proc.readyReadStandardOutput.connect(self._read)
            self.proc.finished.connect(self._finished)
            self.proc.start(cli[0], args)
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.win.statusBar().showMessage("running...")

        def stop(self):
            if self.proc is not None:
                self.proc.kill()

        def _read(self):
            data = bytes(self.proc.readAllStandardOutput()).decode("utf-8", "replace")
            self.console.moveCursor(self.console.textCursor().End)
            self.console.insertPlainText(data)
            self.console.ensureCursorVisible()

        def _finished(self, code, _status):
            self.console.appendPlainText(f"\n[exit {code}]")
            self.proc = None
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.win.statusBar().showMessage(f"run finished (exit {code})")

    class ConfigPage(Page):
        def __init__(self, win):
            super().__init__(win, "Config files", "Edit config.yaml and connectors.yaml directly. Comments are kept.")
            self.tabs = QTabWidget()
            self.cfg_edit = QPlainTextEdit()
            self.cx_edit = QPlainTextEdit()
            for ed in (self.cfg_edit, self.cx_edit):
                ed.setObjectName("console")
            self.tabs.addTab(self.cfg_edit, "config.yaml")
            self.tabs.addTab(self.cx_edit, "connectors.yaml")
            self.root.addWidget(self.tabs, 1)

            bar = QHBoxLayout()
            reload_btn = QPushButton("Reload")
            reload_btn.clicked.connect(self.load_files)
            save = QPushButton("Save")
            save.setObjectName("primary")
            save.clicked.connect(self._save)
            validate = QPushButton("Validate")
            validate.clicked.connect(self._validate)
            bar.addWidget(reload_btn)
            bar.addWidget(save)
            bar.addWidget(validate)
            bar.addStretch(1)
            self.root.addLayout(bar)
            self._loaded = False

        def load_files(self):
            self.cfg_edit.setPlainText(confio.read_text(self.win.cfg_path))
            self.cx_edit.setPlainText(confio.read_text(self.win.cx_path))
            self._loaded = True

        def _save(self):
            confio.write_text(self.win.cfg_path, self.cfg_edit.toPlainText())
            confio.write_text(self.win.cx_path, self.cx_edit.toPlainText())
            self.win.reload()
            self.win.statusBar().showMessage("config files saved")

        def _validate(self):
            result = self.win.run_cli("doctor", ["config"], timeout=30)
            text = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
            box = QMessageBox(self)
            box.setWindowTitle("Validate: doctor config")
            box.setText(text.strip() or f"rc={result.returncode}")
            box.exec()

        def refresh(self):
            # Load once, then leave edits alone so switching tabs never discards
            # unsaved work. Reload is explicit.
            if not self._loaded:
                self.load_files()

    class SettingsPage(Page):
        def __init__(self, win):
            super().__init__(win, "Settings", "Appearance, the workspace location, and the LLM layer.")

            self.root.addWidget(_label("Appearance", "sectionLabel"))
            theme_box = QFormLayout()
            self.theme_combo = QComboBox()
            self.theme_combo.addItems([label for label, _ in THEME_CHOICES])
            self.theme_combo.currentIndexChanged.connect(self._theme_changed)
            theme_box.addRow("theme", self.theme_combo)
            self.root.addLayout(theme_box)
            self.root.addWidget(_divider())
            self.root.addWidget(_label("Workspace", "sectionLabel"))

            ws_box = QFormLayout()
            self.cfg_path = QLineEdit()
            self.cx_path = QLineEdit()
            cfg_row = self._with_browse(self.cfg_path)
            cx_row = self._with_browse(self.cx_path)
            ws_box.addRow("config.yaml", cfg_row)
            ws_box.addRow("connectors.yaml", cx_row)
            apply_paths = QPushButton("Use these paths")
            apply_paths.clicked.connect(self._apply_paths)
            ws_box.addRow("", apply_paths)
            self.root.addLayout(ws_box)
            self.root.addWidget(_divider())
            self.root.addWidget(_label("LLM layer", "sectionLabel"))

            llm_box = QFormLayout()
            self.enabled = QCheckBox("enabled")
            self.provider = QComboBox()
            self.provider.addItems(PROVIDERS)
            self.model = QLineEdit()
            self.ollama_url = QLineEdit()
            self.ollama_model = QLineEdit()
            self.max_tokens = QSpinBox()
            self.max_tokens.setRange(1, 100000)
            llm_box.addRow("", self.enabled)
            llm_box.addRow("provider", self.provider)
            llm_box.addRow("model", self.model)
            llm_box.addRow("ollama base url", self.ollama_url)
            llm_box.addRow("ollama model", self.ollama_model)
            llm_box.addRow("max tokens", self.max_tokens)
            self.root.addLayout(llm_box)

            save = QPushButton("Save LLM settings")
            save.setObjectName("primary")
            save.clicked.connect(self._save_llm)
            self.root.addWidget(save)
            self.root.addStretch(1)

        def _with_browse(self, edit: QLineEdit) -> QWidget:
            row = QWidget()
            lay = QHBoxLayout(row)
            lay.setContentsMargins(0, 0, 0, 0)
            lay.addWidget(edit)
            browse = QPushButton("Browse")
            browse.clicked.connect(lambda: self._browse(edit))
            lay.addWidget(browse)
            return row

        def _browse(self, edit: QLineEdit):
            path, _ = QFileDialog.getOpenFileName(self, "Select file", "", "YAML (*.yaml *.yml);;All files (*)")
            if path:
                edit.setText(path)

        def _apply_paths(self):
            self.win.set_paths(self.cfg_path.text().strip(), self.cx_path.text().strip())
            self.win.pages["Config files"].load_files()

        def _save_llm(self):
            llm = state.LLMSettings(
                enabled=self.enabled.isChecked(),
                provider=self.provider.currentText(),
                model=self.model.text().strip(),
                ollama_base_url=self.ollama_url.text().strip(),
                ollama_model=self.ollama_model.text().strip(),
                max_tokens=self.max_tokens.value(),
            )
            try:
                confio.save_llm(self.win.cfg_path, llm)
            except Exception as exc:  # noqa: BLE001 - surface any write error to the user
                QMessageBox.warning(self, "Save failed", str(exc))
                return
            self.win.reload()
            self.win.statusBar().showMessage("LLM settings saved to config.yaml")

        def _theme_changed(self, idx):
            if 0 <= idx < len(THEME_CHOICES):
                self.win.set_theme(THEME_CHOICES[idx][1])

        def refresh(self):
            ws = self.win.ws
            values = [value for _, value in THEME_CHOICES]
            index = values.index(self.win.theme_pref) if self.win.theme_pref in values else 0
            self.theme_combo.blockSignals(True)
            self.theme_combo.setCurrentIndex(index)
            self.theme_combo.blockSignals(False)
            self.cfg_path.setText(str(self.win.cfg_path))
            self.cx_path.setText(str(self.win.cx_path))
            self.enabled.setChecked(ws.llm.enabled)
            self.provider.setCurrentText(ws.llm.provider)
            self.model.setText(ws.llm.model)
            self.ollama_url.setText(ws.llm.ollama_base_url)
            self.ollama_model.setText(ws.llm.ollama_model)
            self.max_tokens.setValue(ws.llm.max_tokens)

    def _source_rows(ws):
        rows = []
        for s in ws.sources:
            status = "on" if s.enabled else "off"
            detail = s.detail if s.key != "rss" else f"{s.feed_count} feeds"
            rows.append(([s.label, status, detail], s.key))
        return rows

    def _connector_rows(ws):
        return [([c.id, c.type], c.id) for c in ws.connectors]

    def _route_rows(ws):
        return [([r.name, r.selector, ", ".join(r.transports)], r.name) for r in ws.routes]

    def _briefing_rows(ws):
        return [([b.name, b.schedule, b.selector, ", ".join(b.transports)], b.name) for b in ws.briefings]

    class MainWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("CassandraCTI")
            self.resize(1180, 740)
            self.settings = QSettings("CassandraCTI", "gui")
            self.theme_pref = self.settings.value("theme", "system")
            base = state.default_config_dir()
            self.cfg_path = Path(self.settings.value("config_path", str(base / "config.yaml")))
            self.cx_path = Path(self.settings.value("connectors_path", str(base / "connectors.yaml")))
            self.ws = state.load_workspace(self.cfg_path, self.cx_path)

            left = QWidget()
            left.setFixedWidth(212)
            lv = QVBoxLayout(left)
            lv.setContentsMargins(0, 0, 0, 0)
            lv.setSpacing(0)
            lv.addWidget(_label("CASSANDRA", "brand"))
            lv.addWidget(_label("THREAT INTEL CONSOLE", "brandSub"))
            self.nav = QListWidget()
            self.nav.setObjectName("nav")
            self.nav.addItems(NAV)
            lv.addWidget(self.nav, 1)

            self.stack = QStackedWidget()
            self.pages = {
                "Dashboard": DashboardPage(self),
                "Sources": TablePage(
                    self, "Sources", "The feeds and collectors that bring events in.",
                    ["Source", "Status", "Detail"], _source_rows,
                    add_form="add-source",
                    remover=lambda key: ("remove-source", [key], {}),
                    extras=[("Import feeds (CSV)", self._import_feeds)],
                ),
                "Connectors": TablePage(
                    self, "Connectors", "Where briefings and alerts are delivered.",
                    ["Id", "Type"], _connector_rows,
                    add_form="add-connector",
                    remover=lambda key: ("remove-connector", [], {"id": key}),
                    extras=[("Test", self._test_connector)],
                ),
                "Routes": TablePage(
                    self, "Routes", "Which events go to which connectors.",
                    ["Name", "Matches", "Transports"], _route_rows,
                    add_form="routes-add",
                    remover=lambda key: ("routes-remove", [], {"name": key}),
                ),
                "Briefings": TablePage(
                    self, "Briefings", "Periodic LLM recaps of what came in.",
                    ["Name", "Schedule", "Matches", "Transports"], _briefing_rows,
                    add_form="briefing-add",
                    remover=lambda key: ("briefing-remove", [], {"name": key}),
                    extras=[("Run now", self._run_briefing)],
                ),
                "Run": RunPage(self),
                "Config files": ConfigPage(self),
                "Settings": SettingsPage(self),
            }
            for name in NAV:
                self.stack.addWidget(self.pages[name])

            central = QWidget()
            cv = QHBoxLayout(central)
            cv.setContentsMargins(0, 0, 0, 0)
            cv.setSpacing(0)
            cv.addWidget(left)
            cv.addWidget(self.stack, 1)
            self.setCentralWidget(central)

            tb = QToolBar()
            tb.setMovable(False)
            self.addToolBar(tb)
            reload_act = QAction("Reload", self)
            reload_act.setShortcut(QKeySequence("Ctrl+R"))
            reload_act.triggered.connect(self.reload)
            tb.addAction(reload_act)

            self.nav.currentRowChanged.connect(self._nav_changed)
            self.nav.setCurrentRow(0)
            try:
                QApplication.instance().styleHints().colorSchemeChanged.connect(self._on_os_theme)
            except (AttributeError, TypeError):
                pass
            self.reload()

        def set_theme(self, pref):
            self.theme_pref = pref
            self.settings.setValue("theme", pref)
            apply_theme(pref)

        def _on_os_theme(self, *_):
            if self.theme_pref == "system":
                apply_theme(self.theme_pref)

        def _nav_changed(self, row):
            if row < 0:
                return
            self.stack.setCurrentIndex(row)
            self.pages[NAV[row]].refresh()

        def goto(self, name: str):
            self.nav.setCurrentRow(NAV.index(name))

        def set_paths(self, cfg: str, cx: str):
            if cfg:
                self.cfg_path = Path(cfg)
                self.settings.setValue("config_path", cfg)
            if cx:
                self.cx_path = Path(cx)
                self.settings.setValue("connectors_path", cx)
            self.reload()

        def run_cli(self, subcmd, positional=None, options=None, flags=None, timeout=60):
            options = dict(options or {})
            accepts_cfg, accepts_cx = PATH_FLAGS.get(subcmd, (False, False))
            if accepts_cfg and "config" not in options:
                options["config"] = str(self.cfg_path)
            if accepts_cx and "connectors" not in options:
                options["connectors"] = str(self.cx_path)
            return runner.run_cli(subcmd, positional, options, flags, timeout=timeout)

        def report(self, result, ok_message: str):
            if result.ok:
                self.statusBar().showMessage(ok_message)
            else:
                msg = (result.stderr or result.stdout or "").strip() or f"rc={result.returncode}"
                QMessageBox.warning(self, "Command failed", msg)

        def reload(self):
            self.ws = state.load_workspace(self.cfg_path, self.cx_path)
            self.pages[NAV[self.nav.currentRow()]].refresh()
            health = "ok" if self.ws.config_exists else "no config"
            self.statusBar().showMessage(f"{self.cfg_path}   |   {health}   |   " + " ".join(runner.resolve_cli_bin()))

        def _import_feeds(self, _key):
            path, _ = QFileDialog.getOpenFileName(self, "Feeds CSV", "", "CSV (*.csv);;All files (*)")
            if not path:
                return
            result = self.run_cli("import-feeds", [path], {})
            self.report(result, "Feeds imported")
            self.reload()

        def _test_connector(self, key):
            if not key:
                return
            result = self.run_cli("doctor", ["connector"], {"id": key}, timeout=30)
            text = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
            QMessageBox.information(self, f"Test: {key}", text.strip() or f"rc={result.returncode}")

        def _run_briefing(self, key):
            if not key:
                return
            result = self.run_cli("briefing-run", [], {"name": key}, timeout=120)
            self.report(result, f"Briefing '{key}' sent")


def main() -> int:
    if not _HAVE_QT:
        sys.stderr.write(_INSTALL_HINT)
        return 1
    app = QApplication(sys.argv)
    pref = QSettings("CassandraCTI", "gui").value("theme", "system")
    apply_theme(pref)
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
