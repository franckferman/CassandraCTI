"""Transport edge cases: Telegram parse-mode fallback + retry policy, and the
SMTP TLS-mode selection in _send_sync.
"""
import asyncio
import smtplib

import pytest
from tenacity import RetryError

from cassandra_cti.models import Event
from cassandra_cti.transports.telegram import TelegramTransport, TelegramParseError
from cassandra_cti.transports.smtp import SMTPTransport


def _tg(**kw):
    params = dict(bot_token="123:abc", chat_id="@chan", throttle_ms=0)
    params.update(kw)
    return TelegramTransport(**params)


# -- Telegram ---------------------------------------------------------------
def test_send_parse_error_resends_without_parse_mode():
    tr = _tg()
    seen = []
    state = {"n": 0}

    async def fake_post(payload):
        # Snapshot each payload; send() mutates the same dict between calls.
        seen.append(dict(payload))
        state["n"] += 1
        if state["n"] == 1:
            raise TelegramParseError("can't parse entities")

    tr._post = fake_post
    ev = Event(source="rss:X", title="t", summary="s", url="https://e/x")
    asyncio.run(tr.send([ev]))

    assert state["n"] == 2                    # resent once
    assert "parse_mode" in seen[0]            # first attempt kept parse_mode
    assert "parse_mode" not in seen[1]        # retry stripped it (plain text)


def test_post_retries_runtimeerror_but_not_parseerror(monkeypatch):
    async def _fast(*a, **k):
        return None

    monkeypatch.setattr(asyncio, "sleep", _fast)   # skip tenacity backoff waits
    tr = _tg()

    # RuntimeError is transient -> tenacity retries up to stop_after_attempt(5).
    rt = {"n": 0}

    async def boom_runtime(self):
        rt["n"] += 1
        raise RuntimeError("transient")

    monkeypatch.setattr(TelegramTransport, "_ensure_session", boom_runtime)
    with pytest.raises(RetryError):
        asyncio.run(tr._post({"chat_id": "@chan", "text": "x"}))
    assert rt["n"] == 5

    # TelegramParseError is deterministic -> excluded from the retry policy.
    pe = {"n": 0}

    async def boom_parse(self):
        pe["n"] += 1
        raise TelegramParseError("nope")

    monkeypatch.setattr(TelegramTransport, "_ensure_session", boom_parse)
    with pytest.raises(TelegramParseError):
        asyncio.run(tr._post({"chat_id": "@chan", "text": "x"}))
    assert pe["n"] == 1


# -- SMTP -------------------------------------------------------------------
def _fake_smtp_class():
    """A fake context-manager SMTP class + the list of instances it records."""
    created = []

    class Fake:
        def __init__(self, host, port, timeout=None, context=None):
            self.host = host
            self.port = port
            self.timeout = timeout
            self.context = context
            self.actions = []
            created.append(self)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self, context=None):
            self.actions.append("starttls")

        def login(self, username, password):
            self.actions.append(("login", username, password))

        def send_message(self, msg):
            self.actions.append("send_message")

    return Fake, created


def _run_send_sync(monkeypatch, **kw):
    plain_cls, plain_created = _fake_smtp_class()
    ssl_cls, ssl_created = _fake_smtp_class()
    monkeypatch.setattr(smtplib, "SMTP", plain_cls)
    monkeypatch.setattr(smtplib, "SMTP_SSL", ssl_cls)
    params = dict(host="smtp.example.com", to_addrs="soc@example.com", throttle_ms=0)
    params.update(kw)
    tr = SMTPTransport(**params)
    tr._send_sync(object())
    return plain_created, ssl_created


def test_smtp_ssl_uses_smtp_ssl(monkeypatch):
    plain, secure = _run_send_sync(monkeypatch, security="ssl", username="u", password="p")
    assert plain == [] and len(secure) == 1
    s = secure[0]
    assert "starttls" not in s.actions      # implicit TLS: no STARTTLS
    assert "send_message" in s.actions
    assert ("login", "u", "p") in s.actions


def test_smtp_starttls_uses_plain_with_starttls(monkeypatch):
    plain, secure = _run_send_sync(monkeypatch, security="starttls", username="u", password="p")
    assert secure == [] and len(plain) == 1
    s = plain[0]
    assert "starttls" in s.actions
    assert "send_message" in s.actions
    assert ("login", "u", "p") in s.actions


def test_smtp_none_uses_plain_without_starttls(monkeypatch):
    plain, secure = _run_send_sync(monkeypatch, security="none")
    assert secure == [] and len(plain) == 1
    s = plain[0]
    assert "starttls" not in s.actions
    assert "send_message" in s.actions


def test_smtp_login_skipped_without_credentials(monkeypatch):
    plain, secure = _run_send_sync(monkeypatch, security="starttls")
    s = plain[0]
    assert not any(isinstance(a, tuple) and a[0] == "login" for a in s.actions)
    assert "send_message" in s.actions
