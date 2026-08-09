import asyncio
import ssl

import pytest

from cassandra_cti.net import ssl_ctx, read_capped


def test_ssl_ctx_verified_by_default(monkeypatch):
    monkeypatch.delenv("CTI_TLS_NO_VERIFY", raising=False)
    ctx = ssl_ctx()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_ssl_ctx_opt_out_disables_verification(monkeypatch):
    monkeypatch.setenv("CTI_TLS_NO_VERIFY", "1")
    ctx = ssl_ctx()
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False


class _FakeContent:
    def __init__(self, chunks):
        self._chunks = chunks

    async def iter_chunked(self, n):
        for c in self._chunks:
            yield c


class _FakeResp:
    def __init__(self, chunks):
        self.content = _FakeContent(chunks)
        self.url = "http://x"


def test_read_capped_returns_full_body():
    body = asyncio.run(read_capped(_FakeResp([b"ab", b"cd"]), max_bytes=100))
    assert body == b"abcd"


def test_read_capped_rejects_oversized_body():
    with pytest.raises(RuntimeError):
        asyncio.run(read_capped(_FakeResp([b"x" * 10, b"y" * 10]), max_bytes=15))
