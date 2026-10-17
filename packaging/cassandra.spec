# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for the CassandraCTI frozen bundle (onedir). One executable
# with two faces: it opens the GUI by default, and runs the Typer CLI when its
# first argument is the sentinel (see cassandra_cti/frozen_entry.py). Build it
# the spec dir holds relative paths, so it works from the repo root:
#     pyinstaller packaging/cassandra.spec
# The release workflow builds this on ubuntu, macos and windows. QtNetwork is
# excluded because the app never uses it (the CLI owns all networking), which
# also avoids dragging in system TLS/krb5 libraries.
from PyInstaller.utils.hooks import collect_submodules

a = Analysis(
    ["../cassandra_cti/frozen_entry.py"],
    pathex=[".."],
    binaries=[],
    datas=[
        ("../config.example.yaml", "."),
        ("../connectors.example.yaml", "."),
        ("../templates", "templates"),
    ],
    hiddenimports=collect_submodules("cassandra_cti"),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["PySide6.QtNetwork"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="cassandra",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="cassandra",
)
