import os

from cassandra_cti.models import Event
from cassandra_cti.transports.telegram import TelegramTransport

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(ROOT, "templates", "telegram_ransomware.j2"), encoding="utf-8") as _f:
    TPL = _f.read()
with open(os.path.join(ROOT, "templates", "telegram_domains.j2"), encoding="utf-8") as _f:
    DOMAINS_TPL = _f.read()


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


def test_ransomware_template_labels_date_utc():
    text = _render({"group_name": "qilin", "discovered": "2026-07-06 14:02:56"})
    assert "2026-07-06 14:02:56 UTC" in text


def test_ransomware_template_escapes_html():
    text = _render({"group_name": "a<b>c", "activity": "x & y"})
    assert "a&lt;b&gt;c" in text
    assert "x &amp; y" in text


def _render_domains(raw, summary="", url=None):
    tr = TelegramTransport(bot_token="x", chat_id="@x", emojis=False)
    ev = Event(source="red.flag.domains", title="Red Flag Domains", url=url,
               summary=summary, raw=raw)
    return tr._render([ev], template_text=DOMAINS_TPL)


def test_domains_template_shows_count_sample_and_link():
    text = _render_domains({"count": 1234, "date": "2026-07-05"},
                           summary="evil1.com\nevil2.com", url="https://x/list.txt")
    assert "1234" in text
    assert "evil1.com" in text
    assert '<a href="https://x/list.txt">' in text
