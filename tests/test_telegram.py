import asyncio

from cassandra_cti.models import Event
from cassandra_cti.transports import build_transport
from cassandra_cti.transports.telegram import TelegramTransport


def _t(**kw):
    return TelegramTransport(bot_token="123:abc", chat_id="@chan", **kw)


def test_registered_in_factory():
    tr = build_transport("telegram", {"bot_token": "123:abc", "chat_id": "@chan"})
    assert isinstance(tr, TelegramTransport)
    assert tr.api_url.endswith("/bot123:abc/sendMessage")


def test_render_bolds_title_and_escapes_html():
    tr = _t(emojis=False)
    ev = Event(source="rss:X", title="A & B <script>",
               url="https://e/x", summary="1 < 2 & 3")
    text = tr._render([ev])
    assert "<b>A &amp; B &lt;script&gt;</b>" in text   # title bolded + escaped
    assert "1 &lt; 2 &amp; 3" in text                  # summary escaped
    assert "<script>" not in text                      # no raw tag injected


def test_render_truncates_to_telegram_limit():
    tr = _t(emojis=False)
    ev = Event(source="s", title="t", summary="x" * 9000)
    assert len(tr._render([ev])) <= 4096


def test_render_strips_markdown_escape_backslashes():
    tr = _t(emojis=False)
    ev = Event(source="rss:X", title="t", summary=r"\[Mise a jour\] correctif \[1\]")
    text = tr._render([ev])
    assert "\\[" not in text and "\\]" not in text
    assert "[Mise a jour]" in text
    assert "[1]" in text


def test_dry_run_prints_and_skips_network(capsys, monkeypatch):
    monkeypatch.setenv("CTI_DRY_RUN", "1")
    tr = _t()
    asyncio.run(tr.send([Event(source="s", title="hello", url="https://e")]))
    assert "DRYRUN:TELEGRAM" in capsys.readouterr().out
