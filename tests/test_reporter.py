"""Tests for redkit.core.report — JSON/HTML/Markdown generation."""

import json

from redkit.core.models import Finding
from redkit.core.report import Reporter


def make_session_data() -> dict:
    finding = Finding(
        type="XSS",
        severity="HIGH",
        title="Potential reflected XSS",
        detail="detail text",
        evidence="<script>alert(1)</script>",
        module="XSS Tester",
        timestamp="2026-01-01T00:00:00+00:00",
        cvss=6.1,
    )
    return {
        "target": "https://example.com",
        "target_domain": "example.com",
        "start_time": "2026-01-01T00:00:00+00:00",
        "scan_date": "2026-01-01 00:00:00 UTC",
        "scan_history": [{"module": "XSS Tester", "timestamp": "t", "finding_count": 1}],
        "findings": [finding.to_dict()],
        "finding_count": 1,
        "severity_summary": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
    }


def test_generate_writes_all_three_files(tmp_path):
    reporter = Reporter(make_session_data(), output_dir=tmp_path)
    json_path, html_path, md_path = reporter.generate()
    assert json_path.is_file()
    assert html_path.is_file()
    assert md_path.is_file()
    assert json_path.name.startswith("redkit_example.com_")
    assert json_path.suffix == ".json" and html_path.suffix == ".html" and md_path.suffix == ".md"


def test_json_contains_findings(tmp_path):
    reporter = Reporter(make_session_data(), output_dir=tmp_path)
    json_path, _, _ = reporter.generate()
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["finding_count"] == 1
    assert data["findings"][0]["title"] == "Potential reflected XSS"
    assert data["findings"][0]["cvss"] == 6.1


def test_html_contains_finding_escapes_evidence_and_shows_extras(tmp_path):
    reporter = Reporter(make_session_data(), output_dir=tmp_path)
    _, html_path, _ = reporter.generate()
    html = html_path.read_text(encoding="utf-8")
    assert "Potential reflected XSS" in html
    # Evidence is user-controlled reflected content — must be escaped, not raw
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    # CVSS badge and remediation block are rendered
    assert "CVSS 6.1" in html
    assert "HTML-encode output" in html
    # Footer carries the real version, not a hardcoded one
    assert "RedKit v1.0.0" not in html


def test_markdown_is_literal_and_complete(tmp_path):
    """Markdown renders evidence literally (code fences) with remediation."""
    reporter = Reporter(make_session_data(), output_dir=tmp_path)
    _, _, md_path = reporter.generate()
    md = md_path.read_text(encoding="utf-8")
    # Markdown is plain text — evidence must NOT be HTML-escaped
    assert "<script>alert(1)</script>" in md
    assert "&lt;script&gt;" not in md
    assert "**CVSS v3.1 base score:** 6.1" in md
    assert "**Remediation:** HTML-encode output" in md
    assert "Severity Summary" in md
    assert "| HIGH | 1 |" in md


def test_filename_sanitised_without_target_domain(tmp_path):
    data = make_session_data()
    del data["target_domain"]
    data["target"] = "https://weird host.example.com:8443/path"
    reporter = Reporter(data, output_dir=tmp_path)
    json_path, _, _ = reporter.generate()
    name = json_path.name
    assert ":" not in name and " " not in name and "/" not in name
    assert name.startswith("redkit_weird_host.example.com_8443_path_")
