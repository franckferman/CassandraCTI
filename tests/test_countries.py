from cassandra_cti.countries import flag, describe, country_name, COUNTRY_NAMES


def test_flag_from_code():
    assert flag("FR") == "🇫🇷"
    assert flag("us") == "🇺🇸"       # case-insensitive
    assert flag("GB") == "🇬🇧"


def test_flag_invalid_returns_empty():
    assert flag("") == ""
    assert flag(None) == ""
    assert flag("XYZ") == ""         # wrong length
    assert flag("1F") == ""          # non-alpha


def test_describe():
    assert describe("FR") == "France (FR)"
    assert describe("us") == "United States (US)"
    assert describe("") == ""
    assert describe("ZZ") == "ZZ"    # well-formed but unknown -> code as-is


def test_country_name():
    assert country_name("DE") == "Germany"
    assert country_name("ZZ") == "ZZ"
    assert country_name("") == ""


def test_common_codes_present():
    for c in ("US", "FR", "GB", "DE", "CA", "RU", "CZ", "BO", "CN", "JP", "UA"):
        assert c in COUNTRY_NAMES
