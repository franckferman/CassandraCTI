import os

from cassandra_cti.models import Event
from cassandra_cti.transports.telegram import TelegramTransport

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(ROOT, "templates", "telegram_ransomware.j2"), encoding="utf-8") as _f:
    TPL = _f.read()


def _render(raw, url=None, title="Victim by Group"):
    tr = TelegramTransport(bot_token="x", chat_id="@x", emojis=False)
    ev = Event(source="ransomware.live", title=title, url=url, raw=raw)
    return tr._render([ev], template_text=TPL)


def test_ransomware_template_shows_structured_fields():
    text = _render({"group_name": "qilin", "country": "US", "activity": "Construction"})
    assert "<b>Group:</b> qilin" in text
    assert "US" in text and "Construction" in text
    assert "**" not in text                 # no leftover Markdown


def test_ransomware_template_skips_empty_and_na_fields():
    text = _render({"group_name": "qilin", "country": "", "activity": "N/A"})
    assert "Country:" not in text           # empty country skipped
    assert "Sector:" not in text            # "N/A" activity skipped
    assert "N/A" not in text


def test_ransomware_template_escapes_html():
    text = _render({"group_name": "a<b>c", "activity": "x & y"})
    assert "a&lt;b&gt;c" in text
    assert "x &amp; y" in text
