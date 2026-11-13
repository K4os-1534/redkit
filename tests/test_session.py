"""Tests for redkit.core.session — target handling, findings, persistence."""

import pytest

from redkit.core.models import Finding
from redkit.core.session import Session


def test_set_target_prepends_scheme():
    s = Session()
    assert s.set_target("example.com") == "https://example.com"


def test_set_target_rejects_empty():
    s = Session()
    with pytest.raises(ValueError):
        s.set_target("   ")


def test_set_target_rejects_garbage():
    s = Session()
    with pytest.raises(ValueError):
        s.set_target("https://bad url with spaces")


def test_get_target_domain_sanitises():
    s = Session()
    s.set_target("https://example.com:3000/a/b?q=1")
    assert s.get_target_domain() == "example.com_3000_a_b_q_1"


def test_get_target_domain_without_target():
    assert Session().get_target_domain() == "unknown"


def test_add_findings_enriches_and_normalises():
    s = Session()
    s.add_findings("ModA", [{"type": "X", "severity": "high", "title": "t", "detail": "d"}])
    s.add_findings("ModB", [Finding(type="Y", severity="LOW", title="t2", detail="d2")])
    fs = s.get_all_findings()
    assert len(fs) == 2
    assert fs[0].module == "ModA"
    assert fs[0].severity.value == "HIGH"
    assert fs[0].timestamp
    assert fs[1].module == "ModB"
    assert len(s.scan_history) == 2
    assert s.scan_history[0]["finding_count"] == 1


def test_severity_summary_and_filter():
    s = Session()
    s.add_findings(
        "M",
        [
            {"type": "X", "severity": "CRITICAL", "title": "a", "detail": ""},
            {"type": "X", "severity": "INFO", "title": "b", "detail": ""},
            {"type": "X", "severity": "INFO", "title": "c", "detail": ""},
        ],
    )
    summary = s.export_session()["severity_summary"]
    assert summary["CRITICAL"] == 1
    assert summary["INFO"] == 2
    assert summary["HIGH"] == 0
    assert len(s.get_findings_by_severity("info")) == 2


def test_export_session_includes_target_domain():
    s = Session()
    s.set_target("https://example.com")
    data = s.export_session()
    assert data["target_domain"] == "example.com"
    assert data["finding_count"] == 0


def test_save_and_load_roundtrip(tmp_path):
    s = Session()
    s.set_target("https://example.com")
    s.add_findings("M", [{"type": "X", "severity": "HIGH", "title": "t", "detail": "d", "evidence": "e"}])
    path = s.save(tmp_path / "sess.json")

    r = Session.load(path)
    assert r.target == "https://example.com"
    assert len(r.get_all_findings()) == 1
    f = r.get_all_findings()[0]
    assert f.title == "t"
    assert f.severity.value == "HIGH"
    assert f.module == "M"
    assert len(r.scan_history) == 1


def test_load_missing_file_raises(tmp_path):
    with pytest.raises(ValueError, match="not found"):
        Session.load(tmp_path / "nope.json")


def test_load_garbage_file_raises(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("not json at all {{{")
    with pytest.raises(ValueError):
        Session.load(p)
