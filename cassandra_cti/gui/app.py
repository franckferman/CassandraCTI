# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# gui/app.py
#
# PySide6 window. Renders forms.py, builds a command, runs it off the UI thread
# through runner.py, shows stdout/stderr. Never imports the core.
from __future__ import annotations

import shlex
import sys

from . import forms, runner

try:
    from PySide6.QtCore import Qt, QThread, Signal
    from PySide6.QtGui import QAction, QKeySequence
    from PySide6.QtWidgets import (
        QApplication, QCheckBox, QComboBox, QFormLayout, QGroupBox,
        QLabel, QLineEdit, QListWidget, QMainWindow, QPlainTextEdit,
        QSpinBox, QSplitter, QStackedWidget, QTabWidget, QToolBar, QVBoxLayout,
        QWidget,
    )
    _HAVE_QT = True
except ImportError:
    _HAVE_QT = False


_INSTALL_HINT = "PySide6 is not installed. Install the GUI extra with:\n    pip install 'CassandraCTI[gui]'\n"


if _HAVE_QT:

    def _widget_for(fld: forms.Field):
        # One factory per kind. Returns (widget, getter) where getter() yields
        # the current value as a plain python object.
        if fld.kind == "line":
            w = QLineEdit()
            w.setText(str(fld.default or ""))
            return w, w.text
        if fld.kind == "text":
            w = QPlainTextEdit()
            w.setPlainText(str(fld.default or ""))
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

    class FormPage(QWidget):
        # Builds widgets for one subcommand and collects their values.
        def __init__(self, form: forms.Form):
            super().__init__()
            self.form = form
            self._fields = []  # (Field, getter)
            layout = QVBoxLayout(self)
            layout.addWidget(QLabel(form.description))

            if form.positional:
                box = QGroupBox("arguments")
                fl = QFormLayout(box)
                for fld in form.positional:
                    w, getter = _widget_for(fld)
                    if fld.help:
                        w.setToolTip(fld.help)
                    fl.addRow(fld.label, w)
                    self._fields.append((fld, getter))
                layout.addWidget(box)

            if form.options:
                box = QGroupBox("options")
                fl = QFormLayout(box)
                for fld in form.options:
                    w, getter = _widget_for(fld)
                    if fld.help:
                        w.setToolTip(fld.help)
                    fl.addRow(fld.label, w)
                    self._fields.append((fld, getter))
                layout.addWidget(box)

            layout.addStretch(1)

        def collect(self):
            # Returns (positional, options, flags) ready for runner.build_cmd.
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

    class RunWorker(QThread):
        done = Signal(object)

        def __init__(self, subcmd, positional, options, flags):
            super().__init__()
            self._args = (subcmd, positional, options, flags)

        def run(self):
            subcmd, positional, options, flags = self._args
            result = runner.run_cli(subcmd, positional, options, flags, timeout=120)
            self.done.emit(result)

    class MainWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("CassandraCTI")
            self.resize(1000, 640)
            self._worker = None

            self.sidebar = QListWidget()
            self.sidebar.addItems(forms.subcommands())
            self.stack = QStackedWidget()
            self._pages = {}
            for name in forms.subcommands():
                page = FormPage(forms.FORMS[name])
                self._pages[name] = page
                self.stack.addWidget(page)
            self.sidebar.currentRowChanged.connect(self.stack.setCurrentIndex)

            left = QWidget()
            lv = QVBoxLayout(left)
            lv.addWidget(QLabel("subcommand"))
            lv.addWidget(self.sidebar)

            self.cmd_line = QLineEdit()
            self.cmd_line.setReadOnly(True)
            self.output = QPlainTextEdit()
            self.output.setReadOnly(True)
            self.log = QPlainTextEdit()
            self.log.setReadOnly(True)
            mono = self.output.font()
            mono.setFamily("monospace")
            self.output.setFont(mono)
            self.log.setFont(mono)
            self.cmd_line.setFont(mono)

            tabs = QTabWidget()
            tabs.addTab(self.output, "Output")
            tabs.addTab(self.log, "Log")
            right = QWidget()
            rv = QVBoxLayout(right)
            rv.addWidget(QLabel("command"))
            rv.addWidget(self.cmd_line)
            rv.addWidget(tabs)

            mid = QSplitter(Qt.Horizontal)
            mid.addWidget(left)
            mid.addWidget(self.stack)
            mid.addWidget(right)
            mid.setStretchFactor(2, 1)
            self.setCentralWidget(mid)

            tb = QToolBar()
            self.addToolBar(tb)
            self._act(tb, "Run", "Ctrl+G", self.on_run)
            self._act(tb, "Copy command", "Ctrl+Shift+C", self.on_copy)
            self._act(tb, "Clear log", "Ctrl+L", self.on_clear)

            self.sidebar.setCurrentRow(0)
            self.statusBar().showMessage(self._bin_status())

        def _act(self, tb, text, seq, slot):
            a = QAction(text, self)
            a.setShortcut(QKeySequence(seq))
            a.triggered.connect(slot)
            tb.addAction(a)

        def _bin_status(self):
            return "cli: " + shlex.join(runner.resolve_cli_bin())

        def _current(self):
            name = self.sidebar.currentItem().text()
            return name, self._pages[name]

        def _build(self):
            name, page = self._current()
            positional, options, flags = page.collect()
            return name, runner.build_cmd(name, positional, options, flags), (positional, options, flags)

        def on_copy(self):
            _, cmd, _ = self._build()
            QApplication.clipboard().setText(shlex.join(cmd))

        def on_clear(self):
            self.log.clear()
            self.output.clear()

        def on_run(self):
            if self._worker is not None:
                return
            name, cmd, (positional, options, flags) = self._build()
            self.cmd_line.setText(shlex.join(cmd))
            self.log.appendPlainText("$ " + shlex.join(cmd))
            self.statusBar().showMessage("running...")
            self._worker = RunWorker(name, positional, options, flags)
            self._worker.done.connect(self.on_done)
            self._worker.start()

        def on_done(self, result):
            self._worker = None
            self.output.setPlainText(result.stdout or "")
            if result.stderr:
                self.log.appendPlainText(result.stderr.rstrip())
            self.log.appendPlainText(f"[rc={result.returncode}]")
            files = f", {len(result.output_paths)} file(s)" if result.output_paths else ""
            self.statusBar().showMessage(f"rc={result.returncode}{files}  |  {self._bin_status()}")


def main() -> int:
    if not _HAVE_QT:
        sys.stderr.write(_INSTALL_HINT)
        return 1
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
