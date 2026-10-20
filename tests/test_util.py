import pathlib

from cassandra_cti.util import (
    resolve_db_path, make_event_id, expand_env, resolve_template_path,
)


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


def test_tracking_params_do_not_change_event_identity():
    # utm_*/fbclid etc. must not spawn a duplicate of the same article.
    a = make_event_id("rss:X", "https://e.com/a?utm_source=nl&id=1", "T")
    b = make_event_id("rss:X", "https://e.com/a?id=1", "T")
    assert a == b


def test_expand_env(monkeypatch):
    monkeypatch.setenv("CTI_TEST_VAR", "secret")
    assert expand_env("${CTI_TEST_VAR}") == "secret"
    assert expand_env("${CTI_MISSING_VAR}") == "${CTI_MISSING_VAR}"


def test_resolve_template_anchored_to_config_dir(tmp_path, monkeypatch):
    # init copies templates/ next to the config, so a relative template must
    # resolve there regardless of the working directory.
    cfgdir = tmp_path / "cfg"
    (cfgdir / "templates").mkdir(parents=True)
    tpl = cfgdir / "templates" / "t.j2"
    tpl.write_text("x", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    assert resolve_template_path("templates/t.j2", str(cfgdir / "config.yaml")) == str(tpl)


def test_resolve_template_cwd_fallback(tmp_path, monkeypatch):
    # The config dir has no templates/, but the current directory does (the
    # shipped examples, run from the repo root): the CWD fallback resolves it.
    cfgdir = tmp_path / "cfg"
    cfgdir.mkdir()
    cwd = tmp_path / "root"
    (cwd / "templates").mkdir(parents=True)
    (cwd / "templates" / "t.j2").write_text("x", encoding="utf-8")
    monkeypatch.chdir(cwd)
    assert resolve_template_path("templates/t.j2", str(cfgdir / "config.yaml")) == "templates/t.j2"


def test_resolve_template_config_dir_precedes_cwd(tmp_path, monkeypatch):
    cfgdir = tmp_path / "cfg"
    (cfgdir / "templates").mkdir(parents=True)
    (cfgdir / "templates" / "t.j2").write_text("fromcfg", encoding="utf-8")
    cwd = tmp_path / "root"
    (cwd / "templates").mkdir(parents=True)
    (cwd / "templates" / "t.j2").write_text("fromcwd", encoding="utf-8")
    monkeypatch.chdir(cwd)
    resolved = resolve_template_path("templates/t.j2", str(cfgdir / "config.yaml"))
    assert resolved == str(cfgdir / "templates" / "t.j2")
    assert pathlib.Path(resolved).read_text(encoding="utf-8") == "fromcfg"


def test_resolve_template_absolute_and_edge_cases(tmp_path):
    cfg = str(tmp_path / "config.yaml")
    assert resolve_template_path(None, cfg) is None
    assert resolve_template_path("", cfg) is None
    assert resolve_template_path(str(tmp_path / "nope.j2"), cfg) is None
    ok = tmp_path / "ok.j2"
    ok.write_text("x", encoding="utf-8")
    assert resolve_template_path(str(ok), cfg) == str(ok)
    assert resolve_template_path("templates/missing.j2", cfg) is None


def test_resolve_template_expands_tilde(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    (tmp_path / "t.j2").write_text("x", encoding="utf-8")
    assert resolve_template_path("~/t.j2", None) == str(tmp_path / "t.j2")
