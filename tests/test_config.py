"""Tests for redkit.core.config — configuration loading."""

from redkit.core.config import DEFAULTS, load_config


def test_load_config_defaults_when_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = load_config()
    assert cfg["default_threads"] == 10
    assert cfg["verify_ssl"] is True


def test_load_config_reads_cwd_yaml(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yaml").write_text("default_threads: 42\nverify_ssl: false\n")
    cfg = load_config()
    assert cfg["default_threads"] == 42
    assert cfg["verify_ssl"] is False
    # Untouched defaults remain
    assert cfg["default_timeout"] == DEFAULTS["default_timeout"]


def test_load_config_explicit_path(tmp_path):
    cfg_file = tmp_path / "custom.yaml"
    cfg_file.write_text("max_retries: 3\n")
    cfg = load_config(cfg_file)
    assert cfg["max_retries"] == 3


def test_load_config_invalid_yaml_falls_back(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yaml").write_text("a: [unclosed\n")
    cfg = load_config()
    assert cfg["default_threads"] == DEFAULTS["default_threads"]


def test_load_config_non_mapping_yaml_falls_back(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yaml").write_text("- just\n- a\n- list\n")
    cfg = load_config()
    assert cfg["default_threads"] == DEFAULTS["default_threads"]
