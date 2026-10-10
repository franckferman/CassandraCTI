"""RwProSource.fetch graceful degradation (via RansomwarePress).

PRO-only feeds have no fallback, so they must never fail the run: unkeyed or on
any upstream error they log a warning and yield an empty list.
"""
import asyncio
import logging

from cassandra_cti.sources.ransomware_press import RansomwarePress


def test_fetch_without_key_returns_empty_and_does_not_raise():
    src = RansomwarePress(api_key="")
    assert src.api_key == ""
    assert asyncio.run(src.fetch()) == []


def test_fetch_swallows_get_json_error(caplog):
    src = RansomwarePress(api_key="realkey")

    async def _boom(path):
        raise RuntimeError("upstream 500")

    src._get_json = _boom
    with caplog.at_level(logging.WARNING):
        result = asyncio.run(src.fetch())
    assert result == []
    assert "failed" in caplog.text.lower()
