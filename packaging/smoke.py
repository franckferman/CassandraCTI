# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# packaging/smoke.py
#
# Cross-OS smoke test for a built frozen bundle. It runs the executable in
# selftest and CLI modes, asserts the GUI->CLI bridge resolves correctly inside
# the bundle, and runs one real collect/deliver pass in --dry-run so a bundle
# that passes --help but cannot execute the pipeline (a missing data file, a
# path that only resolves outside a frozen build) fails here instead of in
# production. Exit 0 on success, nonzero with a message otherwise. Usage:
#     python packaging/smoke.py <path-to-exe>
import json
import os
import subprocess  # nosec B404 - fixed argv list, shell=False, no shell string
import sys
import tempfile

# A hermetic run: no sources means no network, and --dry-run delivers nothing,
# so this exercises the whole runtime (config load, SQLite store open, source
# and transport construction, one run_once pass) without touching the outside.
_CONFIG = """schema_version: 1
sources: {{}}
transports:
  use: ["smoke"]
routes:
  - name: all
    include_regex: "."
    transports: ["smoke"]
store:
  sqlite_path: "{db}"
metrics:
  enabled: false
"""

_CONNECTORS = """connectors:
  - id: smoke
    type: discord
    params:
      webhook_url: http://smoke.invalid/not-real
"""


def _pipeline_dry_run(exe: str) -> int:
    """Run one --dry-run collection pass through the frozen CLI and assert the
    store was created, proving the bundle runs the pipeline, not just --help."""
    with tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, "smoke.db")
        cfg = os.path.join(d, "config.yaml")
        cx = os.path.join(d, "connectors.yaml")
        # SQLite accepts forward slashes on every OS; a Windows backslash would
        # be an escape inside the double-quoted YAML scalar.
        with open(cfg, "w", encoding="utf-8") as fh:
            fh.write(_CONFIG.format(db=db.replace("\\", "/")))
        with open(cx, "w", encoding="utf-8") as fh:
            fh.write(_CONNECTORS)
        res = subprocess.run(  # nosec B603 - argv is a fixed list, not user input
            [exe, "__cli__", "run", "--dry-run", "--config", cfg, "--connectors", cx],
            capture_output=True, text=True, timeout=120)
        if res.returncode != 0:
            print("pipeline dry-run failed:", res.returncode, res.stderr[:300])
            return 1
        if not os.path.exists(db):
            print("pipeline dry-run did not create the store:", db)
            return 1
    return 0


def main(exe: str) -> int:
    st = subprocess.run(  # nosec B603 - argv is a fixed list, not user input
        [exe, "__selftest__"], capture_output=True, text=True, timeout=120)
    if st.returncode != 0:
        print("selftest failed:", st.returncode, st.stderr)
        return 1
    info = json.loads(st.stdout.strip().splitlines()[-1])
    if not info.get("frozen"):
        print("bundle is not frozen:", info)
        return 1
    bridge = info.get("cli_bridge_cmd", [])
    if len(bridge) != 2 or not bridge[0] or bridge[1] != info.get("sentinel"):
        print("unexpected bridge command:", bridge)
        return 1
    help_ = subprocess.run(  # nosec B603 - argv is a fixed list, not user input
        [exe, "__cli__", "--help"], capture_output=True, text=True, timeout=120)
    if help_.returncode != 0 or "CassandraCTI" not in help_.stdout:
        print("cli --help failed:", help_.returncode, help_.stderr[:200])
        return 1
    rc = _pipeline_dry_run(exe)
    if rc != 0:
        return rc
    print("smoke OK:", json.dumps(info))
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python packaging/smoke.py <path-to-exe>")
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
