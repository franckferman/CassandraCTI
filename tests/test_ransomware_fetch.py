"""RansomwareLive.fetch multi-backend fallback chain.

Order: pro (if api_key) -> v2 -> posts. The first backend that returns a
non-empty list wins; failures and empty results fall through; if every backend
fails, fetch() returns [] rather than raising.
"""
import asyncio

from cassandra_cti.models import Event
from cassandra_cti.sources.ransomware_live import RansomwareLive


def _live(**kw):
    params = dict(lookback_days=0)
    params.update(kw)
    return RansomwareLive(**params)


def test_fetch_pro_error_falls_back_to_v2():
    src = _live(api_key="k")
    v2_events = [Event(source="ransomware.live", title="from v2")]
    calls = []

    async def pro():
        calls.append("pro")
        raise RuntimeError("pro down")

    async def v2():
        calls.append("v2")
        return v2_events

    async def posts():
        calls.append("posts")
        return []

    src._fetch_pro = pro
    src._fetch_v2 = v2
    src._fetch_posts = posts

    assert asyncio.run(src.fetch()) == v2_events
    assert calls == ["pro", "v2"]        # posts never reached


def test_fetch_pro_empty_falls_through_to_v2():
    src = _live(api_key="k")
    v2_events = [Event(source="ransomware.live", title="from v2")]
    calls = []

    async def pro():
        calls.append("pro")
        return []

    async def v2():
        calls.append("v2")
        return v2_events

    async def posts():
        calls.append("posts")
        return []

    src._fetch_pro = pro
    src._fetch_v2 = v2
    src._fetch_posts = posts

    assert asyncio.run(src.fetch()) == v2_events
    assert calls == ["pro", "v2"]        # empty pro result falls through


def test_fetch_all_backends_fail_returns_empty_and_no_raise():
    src = _live(api_key="k")
    calls = []

    async def boom():
        calls.append("x")
        raise RuntimeError("backend down")

    src._fetch_pro = boom
    src._fetch_v2 = boom
    src._fetch_posts = boom

    assert asyncio.run(src.fetch()) == []
    assert len(calls) == 3               # all three attempted


def test_chain_order_with_and_without_api_key():
    with_key = [n for n, _ in RansomwareLive(api_key="k")._chain()]
    without_key = [n for n, _ in RansomwareLive()._chain()]
    assert with_key == ["pro", "v2", "posts"]
    assert without_key == ["v2", "posts"]
