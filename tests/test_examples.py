"""Guard the shipped examples/ configs: each must load, route only to activated
connectors, and reference templates that exist. Offline (load_settings parses,
never fetches)."""
import glob
import os

import pytest
import yaml

from cassandra_cti.config import load_settings

ROOT = os.path.join(os.path.dirname(__file__), os.pardir)
EXAMPLES = sorted(
    d for d in glob.glob(os.path.join(ROOT, "examples", "*")) if os.path.isdir(d)
)


def test_examples_present():
    assert EXAMPLES, "no example scenarios found under examples/"


@pytest.mark.parametrize("d", EXAMPLES, ids=lambda d: os.path.basename(d))
def test_example_loads_routes_and_templates(d):
    cfg = os.path.join(d, "config.yaml")
    cx = os.path.join(d, "connectors.yaml")
    assert os.path.exists(cfg) and os.path.exists(cx), f"{d} missing a YAML file"

    # strict parse (catches quoting / flow-mapping mistakes)
    for f in (cfg, cx):
        with open(f, encoding="utf-8") as fh:
            yaml.safe_load(fh)

    s = load_settings(cfg, cx)
    built = {t.id for t in s.transports}
    assert built, f"{d}: no connectors activated (transports.use)"

    for r in s.routes:
        for tid in (r.transports or []):
            assert tid in built, f"{d}: route '{r.name}' targets unknown connector '{tid}'"
        if r.template:
            tpl = os.path.join(ROOT, r.template)
            assert os.path.exists(tpl), f"{d}: route '{r.name}' template missing: {r.template}"

    for b in s.briefings:
        for tid in (b.transports or []):
            assert tid in built, f"{d}: briefing '{b.name}' targets unknown connector '{tid}'"
        if b.template:
            tpl = os.path.join(ROOT, b.template)
            assert os.path.exists(tpl), f"{d}: briefing '{b.name}' template missing: {b.template}"
