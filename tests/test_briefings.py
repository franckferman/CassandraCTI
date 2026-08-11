"""Briefings core — offline (fake LLM, fake transport, real SQLite store)."""
import asyncio
from datetime import datetime, timezone

from cassandra_cti.briefings import (
    parse_schedule, schedule_label, matches, run_briefings,
)
from cassandra_cti.config import BriefingDef
from cassandra_cti.store import Store
from cassandra_cti.util import make_event_id


class FakeLLM:
    def __init__(self, text="PRIORITISED BRIEF"):
        self.text = text
        self.calls = 0

    async def complete(self, prompt, system=None):
        self.calls += 1
        self.last_prompt = prompt
        return self.text


class Rec:
    def __init__(self):
        self.sent = []

    async def send(self, chunk, title=None, template_text=None):
        self.sent.append({"chunk": list(chunk), "title": title, "template_text": template_text})

    async def aclose(self):
        pass


def _store(tmp_path, sources):
    st = Store(str(tmp_path / "b.db"))
    for i, src in enumerate(sources):
        url = f"https://x/{src}/{i}"
        st.upsert_event(make_event_id(src, url, f"t{i}"), src, url, f"t{i}",
                        "summary", None, tags=["vulnerability"] if src == "cisa.kev" else ["news"],
                        meta={"cve": f"CVE-{i}"} if src == "cisa.kev" else {})
    return st


def _brief(**kw):
    kw.setdefault("name", "vuln-brief")
    kw.setdefault("transports", ["d1"])
    kw.setdefault("include_sources", ["cisa.kev"])
    return BriefingDef(**kw)


class _S:
    def __init__(self, briefings, llm=None):
        self.briefings = briefings
        self.llm = llm or {}


# --------------------------------------------------------------------------- #
def test_parse_schedule_and_label():
    assert parse_schedule("6h").total_seconds() == 6 * 3600
    assert parse_schedule("30m").total_seconds() == 1800
    assert parse_schedule("2d").total_seconds() == 2 * 86400
    assert parse_schedule("garbage").total_seconds() == 24 * 3600
    assert schedule_label("24h") == "1d"
    assert schedule_label("90m") == "90m"


def test_matches_or_semantics_and_catchall():
    b = _brief(include_sources=["cisa.kev"], include_tags=["cert"], include_regex=None)
    assert matches(b, {"source": "cisa.kev", "tags": [], "title": "x"})
    assert matches(b, {"source": "rss:X", "tags": ["cert"], "title": "x"})
    assert not matches(b, {"source": "rss:X", "tags": ["news"], "title": "x"})
    catchall = _brief(include_sources=None, include_tags=None, include_regex=None)
    assert matches(catchall, {"source": "anything", "tags": [], "title": "x"})


def test_sends_when_due(tmp_path):
    st = _store(tmp_path, ["cisa.kev", "cisa.kev", "rss:News"])
    llm, rec = FakeLLM(), Rec()
    n = asyncio.run(run_briefings(_S([_brief(min_items=1)]), st,
                                  {"d1": rec}, dry=False, llm=llm))
    assert n == 1
    assert llm.calls == 1
    assert len(rec.sent) == 1
    ev = rec.sent[0]["chunk"][0]
    assert ev.summary == "PRIORITISED BRIEF"
    assert "Briefing" in rec.sent[0]["title"]
    # only the 2 cisa.kev events were fed to the LLM, not the rss one
    assert st.briefing_last_sent("vuln-brief") is not None


def test_skips_when_not_due(tmp_path):
    st = _store(tmp_path, ["cisa.kev", "cisa.kev"])
    st.mark_briefing_sent("vuln-brief",
                          datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"))
    llm, rec = FakeLLM(), Rec()
    n = asyncio.run(run_briefings(_S([_brief(schedule="24h")]), st, {"d1": rec}, llm=llm))
    assert n == 0 and llm.calls == 0 and rec.sent == []


def test_skips_below_min_items(tmp_path):
    st = _store(tmp_path, ["cisa.kev", "cisa.kev"])
    llm, rec = FakeLLM(), Rec()
    n = asyncio.run(run_briefings(_S([_brief(min_items=5)]), st, {"d1": rec}, llm=llm))
    assert n == 0 and llm.calls == 0 and rec.sent == []


def test_force_bypasses_schedule_and_min(tmp_path):
    st = _store(tmp_path, ["cisa.kev"])
    st.mark_briefing_sent("vuln-brief",
                          datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"))
    llm, rec = FakeLLM(), Rec()
    n = asyncio.run(run_briefings(_S([_brief(min_items=9)]), st, {"d1": rec},
                                  llm=llm, force_all=True))
    assert n == 1 and llm.calls == 1 and len(rec.sent) == 1


def test_dry_run_calls_no_llm_and_marks_nothing(tmp_path):
    st = _store(tmp_path, ["cisa.kev", "cisa.kev"])
    llm, rec = FakeLLM(), Rec()
    n = asyncio.run(run_briefings(_S([_brief(min_items=1)]), st, {"d1": rec},
                                  dry=True, llm=llm))
    assert n == 1                      # would send
    assert llm.calls == 0              # but no LLM call
    assert rec.sent == []              # and no delivery
    assert st.briefing_last_sent("vuln-brief") is None   # and no state change
