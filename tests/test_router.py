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


def test_include_terms_matches_title_summary_and_meta():
    r = Router([_route("watch", include_terms=["Credit Agricole", "BNP"])], {})
    # in the title
    assert len(r.match(Event(source="rss:X", title="Credit Agricole hit by qilin"))) == 1
    # only in the summary (regex on title/source would miss this)
    assert len(r.match(Event(source="rss:X", title="Breach report", summary="victim is BNP Paribas"))) == 1
    # in the meta (e.g. ransomware victim field)
    assert len(r.match(Event(source="ransomware.live", title="v by g",
                             raw={"victim": "Credit Agricole S.A."}))) == 1
    # unrelated event -> no match
    assert len(r.match(Event(source="rss:X", title="unrelated news", summary="nothing"))) == 0


def test_include_terms_is_accent_and_case_insensitive():
    r = Router([_route("watch", include_terms=["credit agricole"])], {})
    assert len(r.match(Event(source="rss:X", title="Crédit Agricole piraté"))) == 1


def test_include_terms_fans_out_with_other_selectors():
    routes = [_route("entity", include_terms=["Gouvernement"]),
              _route("cert", include_tags=["cert"])]
    r = Router(routes, {})
    ev = Event(source="rss:CERT", title="Le Gouvernement visé", tags=["cert"])
    assert sorted(m.name for m in r.match(ev)) == ["cert", "entity"]
