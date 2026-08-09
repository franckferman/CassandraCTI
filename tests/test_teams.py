import asyncio

import pytest

from cassandra_cti.models import Event
from cassandra_cti.transports.teams import TeamsTransport


def _t(**kw):
    kw.setdefault("throttle_ms", 0)
    return TeamsTransport(webhook_url="https://teams.test/webhook/secrettoken", **kw)


def _capture(tr):
    """Replace the instance _post with a capturing no-op (fully offline)."""
    box = {}

    async def fake_post(payload):
        box["payload"] = payload

    tr._post = fake_post
    return box


def test_dry_run_prints_and_skips_post(capsys, monkeypatch):
    monkeypatch.setenv("CTI_DRY_RUN", "1")
    tr = _t()

    async def boom(payload):
        raise AssertionError("_post must not be called during dry run")

    tr._post = boom
    asyncio.run(tr.send([Event(source="s", title="hello", url="https://e/1")]))
    assert "[DRYRUN:TEAMS]" in capsys.readouterr().out


def test_messagecard_shape_single_event_with_url():
    tr = _t(emojis=False)
    box = _capture(tr)
    ev = Event(source="s", title="t", url="https://e.com/x", summary="body")
    asyncio.run(tr.send([ev]))
    payload = box["payload"]
    assert payload["@type"] == "MessageCard"
    assert payload["themeColor"] == tr.theme_color
    assert payload["summary"] == "t"
    assert payload["title"] == "t"
    assert payload["text"]
    actions = payload["potentialAction"]
    assert len(actions) == 1
    assert actions[0]["@type"] == "OpenUri"
    assert actions[0]["targets"][0]["uri"] == "https://e.com/x"


def test_no_openuri_for_single_event_without_url():
    tr = _t(emojis=False)
    box = _capture(tr)
    asyncio.run(tr.send([Event(source="s", title="t", summary="body")]))
    assert box["payload"]["potentialAction"] == []


def test_no_openuri_for_multi_event():
    tr = _t(emojis=False)
    box = _capture(tr)
    events = [
        Event(source="s", title="t1", url="https://e/1"),
        Event(source="s", title="t2", url="https://e/2"),
    ]
    asyncio.run(tr.send(events))
    assert box["payload"]["potentialAction"] == []


def test_throttle_ms_clamped_to_1000():
    tr = _t(throttle_ms=100)
    assert tr.throttle_ms == 1000


def test_429_is_retried_and_honours_retry_after(monkeypatch):
    tr = _t()

    slept = []

    async def fake_sleep(seconds, *args, **kwargs):
        slept.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    calls = {"n": 0}

    class FakeResp:
        status = 429
        headers = {"Retry-After": "3"}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def text(self):
            return "rate limited"

    class FakeSession:
        def post(self, *args, **kwargs):
            calls["n"] += 1
            return FakeResp()

    async def noop_ensure():
        pass

    monkeypatch.setattr(tr, "_ensure_session", noop_ensure)
    monkeypatch.setattr(tr, "_session", FakeSession())

    with pytest.raises(RuntimeError):
        asyncio.run(tr._post({"x": 1}))

    # stop_after_attempt(3): three POST attempts before giving up.
    assert calls["n"] == 3
    # The Retry-After header (3s) was honoured on each 429.
    assert 3 in slept
