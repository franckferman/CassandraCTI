import glob
import os

from jinja2 import Template

from cassandra_cti.models import Event

# Superset of the raw fields the shipped templates reference, so every template
# renders against a realistic context (extra keys are harmless).
RAW = {
    "group_name": "TestGroup", "country": "US", "activity": "Manufacturing",
    "discovered": "2026-07-07T12:00:00", "published": "2026-07-06T12:00:00",
    "website": "victim.example.com", "infostealer": True, "data_size": "5 GB",
    "count": 3, "company": "ACME Corp", "stockticker": "ACME",
    "file_date": "2026-07-07", "link": "https://sec.gov/edgar/x",
    "item105": True, "item801": False, "date": "2026-07-07",
    "victim": "ACME Corp", "domain": "acme.example.com",
    "victims": 10, "groups": 2, "press": 5, "summary": "s",
    "leak_url": "http://abcdef1234567890.onion/blog/victim-x",
    "country_display": "United States (US)", "country_flag": "🇺🇸",
    "infostealer_summary": "15 users, 6 employees",
    "infostealer_stealers": "Lumma (137), RedLine (132)",
    # cisa.kev fields
    "cve": "CVE-2026-1234", "vendor": "Acme", "product": "VPN Gateway",
    "due_date": "2026-08-20", "date_added": "2026-08-01",
    "ransomware_use": True, "required_action": "Apply vendor patch.",
    # abuse.ch fields
    "ioc": "203.0.113.9:443", "ioc_type": "ip:port", "malware": "Emotet",
    "confidence": 100, "status": "online", "feed": "feodo",
}

TDIR = os.path.join(os.path.dirname(__file__), os.pardir, "templates")


def _ctx():
    ev = Event(source="rss:Test Feed", title="A Test Headline",
               url="https://example.com/article", summary="line1\nline2\nline3")
    return dict(title=ev.title, events=[ev], emoji="📰", source=ev.source,
                summary=ev.summary, url=ev.url, raw=RAW)


def test_all_templates_render_without_error():
    ctx = _ctx()
    files = sorted(glob.glob(os.path.join(TDIR, "*.j2")))
    assert files, "no templates found"
    for f in files:
        text = open(f, encoding="utf-8").read()
        out = Template(text).render(**ctx)
        assert out.strip(), f"{os.path.basename(f)} rendered empty"


def test_ransomware_templates_tolerate_empty_raw():
    """A victim missing the infostealer / country / leak_url objects must not
    crash the card; the optional lines are simply omitted."""
    for name in ("ransomware_card.j2", "telegram_ransomware.j2"):
        text = open(os.path.join(TDIR, name), encoding="utf-8").read()
        out = Template(text).render(title="V by g", events=[], emoji="🏴",
                                    source="ransomware.live", summary="N/A",
                                    url="", raw={})
        assert "Group" in out                       # the always-present field renders
        assert "infostealer" not in out.lower()     # absent object -> no line
        assert "onion" not in out.lower()           # absent leak_url -> no onion line


def test_vuln_and_ioc_cards_surface_key_fields():
    """The new source-kind cards must render their defining datum: the CVE for a
    KEV card, the IOC value for an abuse.ch card."""
    for name in ("vuln_card.j2", "telegram_vuln.j2"):
        text = open(os.path.join(TDIR, name), encoding="utf-8").read()
        out = Template(text).render(title="CVE-2026-1234: Acme RCE", events=[],
                                    emoji="🛡️", source="cisa.kev",
                                    summary="Actively exploited RCE.", url="", raw=RAW)
        assert "CVE-2026-1234" in out, f"{name} does not render the CVE"
    for name in ("ioc_card.j2", "telegram_ioc.j2"):
        text = open(os.path.join(TDIR, name), encoding="utf-8").read()
        out = Template(text).render(title="Emotet: 203.0.113.9:443", events=[],
                                    emoji="🦠", source="abuse.ch",
                                    summary="Emotet C2.", url="", raw=RAW)
        assert "203.0.113.9:443" in out, f"{name} does not render the IOC"


def test_new_cards_tolerate_empty_raw():
    """A KEV/IOC card with an empty raw dict must not crash; optional lines are
    simply omitted, the title still renders."""
    for name in ("vuln_card.j2", "telegram_vuln.j2", "ioc_card.j2", "telegram_ioc.j2"):
        text = open(os.path.join(TDIR, name), encoding="utf-8").read()
        out = Template(text).render(title="Fallback title", events=[], emoji="",
                                    source="x", summary="", url="", raw={})
        assert out.strip(), f"{name} rendered empty with empty raw"


def test_default_templates_surface_article_title():
    """The card/embed title is the source name, so the 'default' body templates
    must render the article title themselves."""
    ctx = _ctx()
    for name in ("rss_default.j2", "discord_default.j2",
                 "telegram_default.j2", "smtp_default.j2"):
        text = open(os.path.join(TDIR, name), encoding="utf-8").read()
        out = Template(text).render(**ctx)
        assert "A Test Headline" in out, f"{name} does not render the article title"
