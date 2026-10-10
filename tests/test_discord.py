import asyncio

import aiohttp
import pytest

from cassandra_cti.models import Event
from cassandra_cti.transports.discord import DiscordTransport


def _t(**kw):
    kw.setdefault("throttle_ms", 0)
    return DiscordTransport(webhook_url="https://discord.test/api/webhooks/1/secrettoken", **kw)


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
    assert "[DRYRUN:DISCORD]" in capsys.readouterr().out


def test_title_truncated_to_256():
    tr = _t(emojis=False)
    box = _capture(tr)
    asyncio.run(tr.send([Event(source="s", title="A" * 300, summary="x")]))
    title = box["payload"]["embeds"][0]["title"]
    assert len(title) <= 256
    assert title.endswith("...")


def test_short_title_not_truncated():
    tr = _t(emojis=False)
    box = _capture(tr)
    asyncio.run(tr.send([Event(source="s", title="t", summary="x")]))
    assert box["payload"]["embeds"][0]["title"] == "t"


def test_description_truncated_to_4096():
    tr = _t(emojis=False)
    box = _capture(tr)
    asyncio.run(tr.send([Event(source="s", title="t", summary="x" * 5000)]))
    desc = box["payload"]["embeds"][0]["description"]
    assert len(desc) <= 4096
    assert desc.endswith("... (truncated)")


def test_payload_shape_single_event_with_url():
    tr = _t(emojis=False)
    box = _capture(tr)
    ev = Event(source="s", title="t", url="https://e.com/x", summary="body")
    asyncio.run(tr.send([ev]))
    payload = box["payload"]
    embed = payload["embeds"][0]
    assert embed["title"] == "t"
    assert embed["description"]
    assert embed["color"] == 5814783
    assert embed["url"] == "https://e.com/x"
    # username / avatar_url are omitted when not configured.
    assert "username" not in payload
    assert "avatar_url" not in payload


def test_no_embed_url_for_single_event_without_url():
    tr = _t(emojis=False)
    box = _capture(tr)
    asyncio.run(tr.send([Event(source="s", title="t", summary="body")]))
    assert "url" not in box["payload"]["embeds"][0]


def test_multi_event_render_has_no_embed_url():
    tr = _t(emojis=False)
    box = _capture(tr)
    events = [
        Event(source="s", title="t1", url="https://e/1"),
        Event(source="s", title="t2", url="https://e/2"),
    ]
    asyncio.run(tr.send(events))
    assert "url" not in box["payload"]["embeds"][0]


def test_username_and_avatar_present_only_when_set():
    tr = _t(emojis=False, username="Cassandra", avatar_url="https://a/av.png")
    box = _capture(tr)
    asyncio.run(tr.send([Event(source="s", title="t", url="https://e.com/x")]))
    payload = box["payload"]
    assert payload["username"] == "Cassandra"
    assert payload["avatar_url"] == "https://a/av.png"


def test_invalid_url_raises_valueerror_no_leak_and_not_retried(monkeypatch):
    webhook = "https://discord.test/api/webhooks/1/secrettoken"
    tr = DiscordTransport(webhook_url=webhook, throttle_ms=0, emojis=False)

    calls = {"n": 0}

    class FakeSession:
        def post(self, *args, **kwargs):
            calls["n"] += 1
            raise aiohttp.InvalidURL(webhook)

    async def noop_ensure():
        pass

    monkeypatch.setattr(tr, "_ensure_session", noop_ensure)
    monkeypatch.setattr(tr, "_session", FakeSession())

    with pytest.raises(ValueError) as excinfo:
        asyncio.run(tr.send([Event(source="s", title="t")]))

    # The clean ValueError must not leak the (possibly secret) webhook URL.
    assert webhook not in str(excinfo.value)
    # ValueError is a non-retryable exception: exactly one attempt.
    assert calls["n"] == 1
