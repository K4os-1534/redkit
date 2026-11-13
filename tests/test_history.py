"""Tests for redkit.core.history — recent targets and module options."""

from redkit.core.history import (
    history_path,
    load_history,
    load_module_options,
    recent_targets,
    record_module_options,
    record_target,
)


def test_record_target_dedupes_and_orders(tmp_path):
    p = tmp_path / "hist.json"
    record_target(p, "https://a.com")
    record_target(p, "https://b.com")
    record_target(p, "https://a.com")  # moves to front
    assert recent_targets(p) == ["https://a.com", "https://b.com"]


def test_record_target_caps_at_ten(tmp_path):
    p = tmp_path / "hist.json"
    for i in range(12):
        record_target(p, f"https://host{i}.com")
    targets = recent_targets(p)
    assert len(targets) == 10
    assert targets[0] == "https://host11.com"


def test_record_target_disabled_is_noop(tmp_path):
    p = tmp_path / "hist.json"
    record_target(p, "https://a.com", enabled=False)
    assert recent_targets(p) == []


def test_module_options_roundtrip_excludes_target(tmp_path):
    p = tmp_path / "hist.json"
    options = {
        "target": {"value": "https://x.com"},  # must be excluded
        "param": {"value": "q"},
        "threads": {"value": 7},
        "empty": {"value": None},  # must be excluded
    }
    record_module_options(p, "XSS Tester", options)
    saved = load_module_options(p, "XSS Tester")
    assert saved == {"param": "q", "threads": 7}
    assert load_module_options(p, "Other Module") == {}


def test_corrupt_history_file_starts_fresh(tmp_path):
    p = tmp_path / "hist.json"
    p.write_text("{{{ not json")
    assert load_history(p) == {"targets": [], "modules": {}}
    record_target(p, "https://a.com")
    assert recent_targets(p) == ["https://a.com"]


def test_history_path_override_from_config(tmp_path):
    config = {"history_file": str(tmp_path / "custom.json")}
    assert history_path(config) == tmp_path / "custom.json"
    assert history_path({}) == history_path(None)  # both fall back to default
