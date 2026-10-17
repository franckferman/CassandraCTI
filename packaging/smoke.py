# CassandraCTI - Modular Cyber Threat Intelligence Aggregator
# Copyright (C) 2025 Franck Ferman
# packaging/smoke.py
#
# Cross-OS smoke test for a built frozen bundle. Runs the executable in selftest
# and CLI modes and asserts the GUI->CLI bridge resolves correctly inside the
# bundle. Exit 0 on success, nonzero with a message otherwise. Usage:
#     python packaging/smoke.py <path-to-exe>
import json
import subprocess  # nosec B404 - fixed argv list, shell=False, no shell string
import sys


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
    print("smoke OK:", json.dumps(info))
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python packaging/smoke.py <path-to-exe>")
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
