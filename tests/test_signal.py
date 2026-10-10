import asyncio

import pytest

from cassandra_cti.models import Event
from cassandra_cti.transports.signal import SignalTransport


def _t(**kw):
    kw.setdefault("throttle_ms", 0)
    kw.setdefault("emojis", False)
    kw.setdefault("api_url", "http://localhost:8080")
    kw.setdefault("number", "+33600000000")
    kw.setdefault("recipients", ["+33611111111", "group.AAA="])
    return SignalTransport(**kw)


def _capture(tr):
    box = {}

    async def fake_post(payload):
        box["payload"] = payload

    tr._post = fake_post
    return box


def test_dry_run_prints_and_skips_post(capsys):
    tr = _t()
    import os
    os.environ["CTI_DRY_RUN"] = "1"

    async def boom(payload):
        raise AssertionError("_post must not be called during dry run")

    tr._post = boom
    asyncio.run(tr.send([Event(source="s", title="hello", url="https://e/1")]))
    assert "[DRYRUN:SIGNAL]" in capsys.readouterr().out


def test_payload_shape_number_and_group():
    tr = _t()
    box = _capture(tr)
    asyncio.run(tr.send([Event(source="cisa.kev", title="CVE-1", url="https://e/1", summary="body")]))
    p = box["payload"]
    assert p["number"] == "+33600000000"
    # one connector can target a number AND a group at once
    assert p["recipients"] == ["+33611111111", "group.AAA="]
    assert "CVE-1" in p["message"] and "https://e/1" in p["message"]


def test_recipients_accepts_comma_string():
    tr = _t(recipients="+33611111111, group.AAA=")
    assert tr.recipients == ["+33611111111", "group.AAA="]


@pytest.mark.parametrize("recips", [
    ["+33611111111"],                        # number only
    ["group.AAA="],                          # group only
    ["+33611111111", "group.AAA="],          # both
])
def test_recipients_number_group_or_both(recips):
    tr = _t(recipients=recips)
    box = _capture(tr)
    asyncio.run(tr.send([Event(source="s", title="t", summary="b")]))
    assert box["payload"]["recipients"] == recips


def test_multi_event_render_lists_titles():
    tr = _t()
    box = _capture(tr)
    evs = [Event(source="s", title="t1", url="https://e/1"),
           Event(source="s", title="t2", url="https://e/2")]
    asyncio.run(tr.send(evs))
    msg = box["payload"]["message"]
    assert "t1" in msg and "t2" in msg


def test_text_mode_only_when_set():
    box = _capture(_t := SignalTransport(api_url="http://x", number="+1",
                                         recipients=["+2"], emojis=False, throttle_ms=0))
    asyncio.run(_t.send([Event(source="s", title="t", summary="b")]))
    assert "text_mode" not in box["payload"]

    box2 = _capture(t2 := SignalTransport(api_url="http://x", number="+1", recipients=["+2"],
                                          emojis=False, throttle_ms=0, text_mode="styled"))
    asyncio.run(t2.send([Event(source="s", title="t", summary="b")]))
    assert box2["payload"]["text_mode"] == "styled"


@pytest.mark.parametrize("kw", [
    {"api_url": "", "number": "+1", "recipients": ["+2"]},
    {"api_url": "http://x", "number": "", "recipients": ["+2"]},
    {"api_url": "http://x", "number": "+1", "recipients": []},
])
def test_missing_config_raises(kw):
    with pytest.raises(ValueError):
        SignalTransport(**kw)
