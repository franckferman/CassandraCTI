import asyncio

from cassandra_cti.net import valid_http_url
from cassandra_cti.transports.discord import DiscordTransport
from cassandra_cti.transports.teams import TeamsTransport
from cassandra_cti.models import Event


def test_valid_http_url():
    assert valid_http_url("https://example.com/a")
    assert valid_http_url("http://abcdef1234.onion/x")   # dotted host (.onion)
    assert not valid_http_url("https://x")               # no dotted host -> Discord 400
    assert not valid_http_url("")
    assert not valid_http_url(None)
    assert not valid_http_url("javascript:alert(1)")


def _capture(tr):
    box = {}

    async def fake_post(payload):
        box["payload"] = payload

    tr._post = fake_post
    return box


def test_discord_omits_invalid_embed_url_but_keeps_valid():
    bad = DiscordTransport("https://discord/wh", throttle_ms=0, emojis=False)
    box = _capture(bad)
    asyncio.run(bad.send([Event(source="s", title="t", url="https://x", summary="b")]))
    assert "url" not in box["payload"]["embeds"][0]      # invalid -> dropped, message still sent

    good = DiscordTransport("https://discord/wh", throttle_ms=0, emojis=False)
    box2 = _capture(good)
    asyncio.run(good.send([Event(source="s", title="t", url="https://good.com/x", summary="b")]))
    assert box2["payload"]["embeds"][0]["url"] == "https://good.com/x"


def test_teams_omits_invalid_openuri():
    tr = TeamsTransport("https://teams/wh", throttle_ms=0, emojis=False)
    box = _capture(tr)
    asyncio.run(tr.send([Event(source="s", title="t", url="https://x", summary="b")]))
    assert box["payload"]["potentialAction"] == []       # invalid url -> no OpenUri action
