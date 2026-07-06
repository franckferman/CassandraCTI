from cassandra_cti.config import RouteDef
from cassandra_cti.models import Event
from cassandra_cti.router import Router


def _route(name, **kw):
    return RouteDef(name=name, transports=[name + "-t"], **kw)


def test_event_fans_out_to_every_matching_route():
    routes = [
        _route("cert", include_tags=["cert"]),
        _route("firehose", include_sources=["rss:"]),
    ]
    r = Router(routes, {})
    ev = Event(source="rss:CERT", title="x", tags=["cert"])
    assert [m.name for m in r.match(ev)] == ["cert", "firehose"]


def test_source_prefix_vs_exact_match():
    routes = [
        _route("prefix", include_sources=["rss:"]),
        _route("exact", include_sources=["ransomware.live"]),
    ]
    r = Router(routes, {})
    assert [m.name for m in r.match(Event(source="rss:Krebs", title="t"))] == ["prefix"]
    assert [m.name for m in r.match(Event(source="ransomware.live", title="t"))] == ["exact"]


def test_regex_matches_on_title():
    r = Router([_route("crit", include_regex="(?i)cve")], {})
    assert len(r.match(Event(source="rss:X", title="New CVE-2025-1"))) == 1
    assert len(r.match(Event(source="rss:X", title="nothing here"))) == 0
