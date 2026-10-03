"""Shared test fixtures + a hard offline guard.

Every test must be offline: `_no_network` (autouse) makes any real aiohttp
request raise, so an accidentally un-mocked transport/source fails loudly
instead of hitting the internet in CI.
"""
import os

import aiohttp
import pytest


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    async def _blocked(*args, **kwargs):
        raise AssertionError("real network call attempted in a test (mock it)")
    monkeypatch.setattr(aiohttp.ClientSession, "_request", _blocked)


@pytest.fixture(autouse=True)
def _restore_env():
    """Snapshot and restore os.environ around every test. CLI commands use env
    vars (CTI_DRY_RUN, CTI_LOGLEVEL, …) as a side channel, so a test invoking
    e.g. `run --dry-run` must not leak CTI_DRY_RUN into later tests."""
    snapshot = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(snapshot)


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
