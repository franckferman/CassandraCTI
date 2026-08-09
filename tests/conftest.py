"""Shared test fixtures + a hard offline guard.

Every test must be offline: `_no_network` (autouse) makes any real aiohttp
request raise, so an accidentally un-mocked transport/source fails loudly
instead of hitting the internet in CI.
"""
import aiohttp
import pytest


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    async def _blocked(*args, **kwargs):
        raise AssertionError("real network call attempted in a test (mock it)")
    monkeypatch.setattr(aiohttp.ClientSession, "_request", _blocked)


class FakeTransport:
    """Records sends instead of hitting the network."""

    def __init__(self, batching=None):
        self.batch_cfg = batching or {}
        self.sent = []

    async def send(self, chunk, title=None, template_text=None):
        self.sent.append({"chunk": list(chunk), "title": title,
                          "template_text": template_text})

    async def aclose(self):
        pass


@pytest.fixture
def fake_transport():
    return FakeTransport
