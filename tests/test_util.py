from cassandra_cti.util import resolve_db_path, make_event_id, expand_env


def test_resolve_db_path_relative_anchored_to_config_dir(tmp_path):
    cfg = tmp_path / "sub" / "config.yaml"
    resolved = resolve_db_path(".cassandra_cti.db", str(cfg))
    assert resolved == str(tmp_path / "sub" / ".cassandra_cti.db")


def test_resolve_db_path_absolute_is_left_unchanged(tmp_path):
    abs_db = tmp_path / "x.db"
    assert resolve_db_path(str(abs_db), str(tmp_path / "config.yaml")) == str(abs_db)


def test_make_event_id_is_url_based_and_deterministic():
    a = make_event_id("rss:X", "https://e.com/a", "Title")
    b = make_event_id("rss:X", "https://e.com/a", "Different title")
    c = make_event_id("rss:Y", "https://e.com/a", "Title")
    assert a == b       # url present -> title ignored
    assert a != c       # source is part of the identity


def test_expand_env(monkeypatch):
    monkeypatch.setenv("CTI_TEST_VAR", "secret")
    assert expand_env("${CTI_TEST_VAR}") == "secret"
    assert expand_env("${CTI_MISSING_VAR}") == "${CTI_MISSING_VAR}"
