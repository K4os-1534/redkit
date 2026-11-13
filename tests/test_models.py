"""Tests for redkit.core.models — Severity and Finding."""

from redkit.core.models import Finding, Severity, remediation_for


def test_severity_parse_accepts_case_insensitive_strings():
    assert Severity.parse("critical") is Severity.CRITICAL
    assert Severity.parse("High") is Severity.HIGH


def test_severity_parse_passthrough_and_fallback():
    assert Severity.parse(Severity.LOW) is Severity.LOW
    assert Severity.parse("not-a-severity") is Severity.INFO


def test_finding_normalises_severity():
    f = Finding(type="XSS", severity="high", title="t", detail="d")
    assert f.severity is Severity.HIGH


def test_finding_to_dict_roundtrip():
    f = Finding(
        type="XSS",
        severity="HIGH",
        title="t",
        detail="d",
        evidence="e",
        module="m",
        timestamp="ts",
    )
    d = f.to_dict()
    assert d["severity"] == "HIGH"
    assert Finding.from_dict(d) == f


def test_finding_from_dict_tolerates_missing_fields():
    f = Finding.from_dict({})
    assert f.severity is Severity.INFO
    assert f.title == ""
    assert f.type == ""


def test_cvss_roundtrip():
    f = Finding(type="SQL Injection", severity="CRITICAL", title="t", detail="d", cvss=9.1)
    d = f.to_dict()
    assert d["cvss"] == 9.1
    assert Finding.from_dict(d).cvss == 9.1


def test_cvss_defaults_to_none_and_tolerates_garbage():
    assert Finding(type="T", severity="INFO", title="t", detail="d").cvss is None
    assert Finding.from_dict({"cvss": "not-a-number"}).cvss is None


def test_remediation_lookup():
    assert "parameterised queries" in remediation_for("SQL Injection").lower()
    assert remediation_for("Totally Unknown Type") == ""
