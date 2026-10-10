import asyncio

import pytest

from cassandra_cti.models import Event
from cassandra_cti.transports import build_transport
from cassandra_cti.transports.smtp import SMTPTransport


def _t(**kw):
    params = dict(host="smtp.example.com", to_addrs="soc@example.com")
    params.update(kw)
    return SMTPTransport(**params)


def test_registered_in_factory():
    tr = build_transport("smtp", {"host": "h", "to_addrs": ["a@b.c"]})
    assert isinstance(tr, SMTPTransport)


def test_render_subject_prefix_and_html_escape():
    tr = _t(emojis=False, subject_prefix="[CTI]")
    ev = Event(source="rss:X", title="Bug <b>", url="https://e/x", summary="a < b & c")
    subject, body_html = tr._render([ev])
    assert subject == "[CTI] Bug <b>"                 # subject is plain text
    assert "a &lt; b &amp; c" in body_html            # body is HTML-escaped
    assert "<b>" not in body_html                     # no raw tag injected


def test_build_message_is_multipart_plain_and_html():
    tr = _t()
    msg = tr._build_message("[CTI] hi", "<p>hello <b>world</b></p>")
    assert msg["To"] == "soc@example.com"
    assert msg.get_content_type() == "multipart/alternative"
    types = {p.get_content_type() for p in msg.iter_parts()}
    assert types == {"text/plain", "text/html"}


def test_to_addrs_accepts_comma_string():
    tr = _t(to_addrs="a@x.com, b@y.com")
    assert tr.to_addrs == ["a@x.com", "b@y.com"]


def test_missing_recipient_raises():
    tr = _t(to_addrs=[])
    with pytest.raises(ValueError):
        asyncio.run(tr.send([Event(source="s", title="t")]))


def test_send_calls_smtp_without_network(monkeypatch):
    tr = _t()
    captured = {}
    tr._send_sync = lambda msg: captured.setdefault("msg", msg)
    asyncio.run(tr.send([Event(source="s", title="hello", url="https://e", summary="body")]))
    assert captured["msg"]["To"] == "soc@example.com"
    assert captured["msg"]["Subject"].startswith("[CTI]")


def test_dry_run_prints_and_skips_send(capsys, monkeypatch):
    monkeypatch.setenv("CTI_DRY_RUN", "1")
    tr = _t()

    def _boom(msg):
        raise AssertionError("must not send in dry-run")

    tr._send_sync = _boom
    asyncio.run(tr.send([Event(source="s", title="hello")]))
    assert "DRYRUN:SMTP" in capsys.readouterr().out
