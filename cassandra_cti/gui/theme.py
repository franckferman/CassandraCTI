# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# gui/theme.py
#
# The visual identity, lifted from the docs site so the desktop app and the
# landing page read as one product: amber accent, cyan and green for state,
# monospace for anything machine-written. Two palettes, dark and light; the app
# picks one (or follows the OS). Pure data and strings, no Qt import, so it is
# testable without a display.
from __future__ import annotations

# Shared fonts. Space Mono / Space Grotesk are the site fonts; the rest are the
# usual desktop fallbacks when they are not installed.
MONO = "'Space Mono', 'JetBrains Mono', 'DejaVu Sans Mono', Consolas, monospace"
SANS = "'Space Grotesk', 'Inter', 'Segoe UI', sans-serif"

# Dark palette (same tokens as docs/index.html).
_DARK = {
    "bg": "#04050a",
    "bg2": "#070910",
    "panel": "#0b0e16",
    "panel2": "#10131d",
    "text": "#e8e6df",
    "text_mid": "#a09e97",
    "text_dim": "#6b6a65",
    "amber": "#f59e0b",
    "amber_dim": "#92600a",
    "amber_hover": "#ffc436",
    "primary_text": "#1a1200",
    "green": "#22c55e",
    "red": "#dc2626",
    "border": "rgba(245, 158, 11, 0.14)",
    "border_soft": "rgba(232, 230, 223, 0.08)",
    "console_bg": "#020307",
    "console_fg": "#e8e6df",
}

# Light palette: the same identity, legible on white. The amber is darkened so
# it keeps contrast as text on a light panel.
_LIGHT = {
    "bg": "#f6f6f3",
    "bg2": "#eceae4",
    "panel": "#ffffff",
    "panel2": "#f1efe9",
    "text": "#1b1a17",
    "text_mid": "#55524c",
    "text_dim": "#8a877f",
    "amber": "#b45309",
    "amber_dim": "#d97706",
    "amber_hover": "#c2620a",
    "primary_text": "#ffffff",
    "green": "#16a34a",
    "red": "#dc2626",
    "border": "rgba(180, 83, 9, 0.22)",
    "border_soft": "rgba(27, 26, 23, 0.10)",
    "console_bg": "#faf9f6",
    "console_fg": "#1b1a17",
}

# The dark tokens are also exposed as module constants, for back-compat and as
# the default reference palette.
BG = _DARK["bg"]
AMBER = _DARK["amber"]


def palette(mode: str = "dark") -> dict:
    """Return the token dict for a mode. Anything but 'light' is dark."""
    return dict(_LIGHT if mode == "light" else _DARK)


def stylesheet(mode: str = "dark") -> str:
    """The application-wide QSS for a mode ('dark' or 'light'). One template, so
    a palette change is a one-line edit above."""
    p = palette(mode)
    bg = p["bg"]
    bg2 = p["bg2"]
    panel = p["panel"]
    panel2 = p["panel2"]
    text = p["text"]
    text_mid = p["text_mid"]
    text_dim = p["text_dim"]
    amber = p["amber"]
    amber_dim = p["amber_dim"]
    amber_hover = p["amber_hover"]
    primary_text = p["primary_text"]
    green = p["green"]
    red = p["red"]
    border = p["border"]
    border_soft = p["border_soft"]
    console_bg = p["console_bg"]
    console_fg = p["console_fg"]
    return f"""
    QMainWindow, QWidget {{
        background: {bg};
        color: {text};
        font-family: {SANS};
        font-size: 13px;
    }}
    QLabel#brand {{
        color: {amber};
        font-family: {MONO};
        font-size: 17px;
        font-weight: bold;
        letter-spacing: 3px;
        padding: 16px 14px 4px 14px;
    }}
    QLabel#brandSub {{
        color: {text_dim};
        font-family: {MONO};
        font-size: 10px;
        letter-spacing: 1px;
        padding: 0 14px 14px 14px;
    }}
    QLabel#pageTitle {{
        color: {text};
        font-size: 20px;
        font-weight: bold;
        padding: 2px 0 2px 0;
    }}
    QLabel#pageHint {{
        color: {text_mid};
        font-size: 12px;
        padding-bottom: 6px;
    }}
    QLabel#sectionLabel {{
        color: {amber};
        font-family: {MONO};
        font-size: 10px;
        letter-spacing: 2px;
        padding: 14px 14px 4px 14px;
    }}
    QListWidget#nav {{
        background: {bg2};
        border: none;
        outline: 0;
        padding: 4px 6px;
    }}
    QListWidget#nav::item {{
        color: {text_mid};
        padding: 9px 12px;
        border-radius: 6px;
        margin: 1px 4px;
    }}
    QListWidget#nav::item:hover {{
        background: {panel};
        color: {text};
    }}
    QListWidget#nav::item:selected {{
        background: {panel2};
        color: {amber};
        border-left: 2px solid {amber};
    }}
    QFrame#card {{
        background: {panel};
        border: 1px solid {border};
        border-radius: 10px;
    }}
    QFrame#divider {{
        background: {border_soft};
        max-height: 1px;
        min-height: 1px;
    }}
    QLabel#stat {{
        font-family: {MONO};
        font-size: 26px;
        font-weight: bold;
        color: {text};
        background: transparent;
        border: none;
    }}
    QLabel#statLabel {{
        color: {text_dim};
        font-family: {MONO};
        font-size: 10px;
        letter-spacing: 1px;
        background: transparent;
        border: none;
    }}
    QLabel#healthOk {{ color: {green}; font-family: {MONO}; }}
    QLabel#healthWarn {{ color: {amber}; font-family: {MONO}; }}
    QLabel#healthBad {{ color: {red}; font-family: {MONO}; }}
    QLineEdit, QPlainTextEdit, QSpinBox, QComboBox {{
        background: {bg2};
        color: {text};
        border: 1px solid {border_soft};
        border-radius: 6px;
        padding: 6px 8px;
        selection-background-color: {amber_dim};
    }}
    QLineEdit:focus, QPlainTextEdit:focus, QSpinBox:focus, QComboBox:focus {{
        border: 1px solid {amber};
    }}
    QComboBox::drop-down {{ border: none; width: 18px; }}
    QComboBox QAbstractItemView {{
        background: {panel2};
        color: {text};
        selection-background-color: {amber_dim};
        border: 1px solid {border};
    }}
    QPlainTextEdit#console {{
        background: {console_bg};
        color: {console_fg};
        font-family: {MONO};
        font-size: 12px;
        border: 1px solid {border};
        border-radius: 8px;
    }}
    QPushButton {{
        background: {panel2};
        color: {text};
        border: 1px solid {border_soft};
        border-radius: 6px;
        padding: 7px 14px;
    }}
    QPushButton:hover {{ border: 1px solid {amber}; color: {amber}; }}
    QPushButton:disabled {{ color: {text_dim}; border: 1px solid {border_soft}; }}
    QPushButton#primary {{
        background: {amber};
        color: {primary_text};
        font-weight: bold;
        border: none;
    }}
    QPushButton#primary:hover {{ background: {amber_hover}; }}
    QPushButton#danger:hover {{ border: 1px solid {red}; color: {red}; }}
    QTableWidget {{
        background: {panel};
        color: {text};
        border: 1px solid {border};
        border-radius: 8px;
        gridline-color: {border_soft};
        selection-background-color: {panel2};
        selection-color: {amber};
    }}
    QHeaderView::section {{
        background: {bg2};
        color: {text_dim};
        font-family: {MONO};
        font-size: 10px;
        letter-spacing: 1px;
        border: none;
        border-bottom: 1px solid {border};
        padding: 7px 8px;
    }}
    QTableWidget::item {{ padding: 4px 8px; }}
    QTabWidget::pane {{ border: 1px solid {border}; border-radius: 8px; top: -1px; }}
    QTabBar::tab {{
        background: transparent;
        color: {text_dim};
        font-family: {MONO};
        padding: 6px 14px;
        border: none;
    }}
    QTabBar::tab:selected {{ color: {amber}; border-bottom: 2px solid {amber}; }}
    QToolBar {{ background: {bg2}; border: none; spacing: 4px; padding: 3px; }}
    QStatusBar {{
        background: {bg2};
        color: {text_dim};
        font-family: {MONO};
        font-size: 11px;
    }}
    QScrollBar:vertical {{ background: {bg}; width: 10px; margin: 0; }}
    QScrollBar::handle:vertical {{ background: {panel2}; border-radius: 5px; min-height: 30px; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}
    QToolTip {{
        background: {panel2};
        color: {text};
        border: 1px solid {amber};
    }}
    """
