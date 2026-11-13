"""Tests for redkit.modules.vuln_scan — XSS, SQLi baseline logic, LFI."""

import time
from urllib.parse import parse_qs, unquote, urlparse

from redkit.core.http_client import HttpClient
from redkit.modules.vuln_scan.lfi_tester import LfiTester
from redkit.modules.vuln_scan.xss_tester import XssTester


def _query_value(url: str, key: str) -> str:
    return (parse_qs(urlparse(url).query).get(key) or [""])[0]


# ---------------------------------------------------------------------
# XSS
# ---------------------------------------------------------------------


def test_reflection_context_script():
    body = '<html><script>var q = "PAYLOAD";</script></html>'
    assert XssTester._reflection_context(body, body.index("PAYLOAD")) == "script"


def test_reflection_context_comment():
    body = "<html><!-- PAYLOAD --></html>"
    assert XssTester._reflection_context(body, body.index("PAYLOAD")) == "html-comment"


def test_reflection_context_attribute():
    body = "<html><a href='PAYLOAD'>x</a></html>"
    assert XssTester._reflection_context(body, body.index("PAYLOAD")) == "tag-attribute"


def test_reflection_context_body():
    body = "<html><p>PAYLOAD</p></html>"
    assert XssTester._reflection_context(body, body.index("PAYLOAD")) == "body"


def test_xss_module_single_finding_with_context(make_response, monkeypatch):
    module = XssTester()
    module.set_option("target", "https://t.local/search")
    module.set_option("param", "q")

    def fake_request(self, method, url, **kw):
        q = _query_value(url, "q")
        return make_response(200, f"<html><p>Results for {q}</p></html>", url=url)

    monkeypatch.setattr(HttpClient, "request", fake_request)
    module.run()

    findings = module.get_findings()
    assert len(findings) == 1  # de-duplicated across all reflected payloads
    assert findings[0].severity.value == "HIGH"
    assert "Potential reflected XSS" in findings[0].title
    assert "body" in findings[0].detail


def test_xss_comment_only_reflection_is_medium(make_response, monkeypatch):
    module = XssTester()
    module.set_option("target", "https://t.local/search")
    module.set_option("param", "q")

    def fake_request(self, method, url, **kw):
        q = _query_value(url, "q")
        # Only payloads that do not close the comment are reflected
        if (
            "-->" in q
            or "</style" in q.lower()
            or "</title" in q.lower()
            or "</textarea" in q.lower()
            or "srcdoc" in q
            or "onload" in q
            or "onerror" in q
            or "onfocus" in q
            or "ontoggle" in q
            or "onmouseover" in q
            or "oNcliCk" in q
            or "javascript" in q
        ):
            return make_response(200, "<html><p>no reflection</p></html>", url=url)
        body = f"<html><!-- echo: {q} --></html>"
        return make_response(200, body, url=url)

    monkeypatch.setattr(HttpClient, "request", fake_request)
    module.run()

    findings = module.get_findings()
    assert len(findings) == 1
    assert findings[0].severity.value == "MEDIUM"
    assert "html-comment" in findings[0].detail


def test_xss_no_reflection_no_finding(make_response, monkeypatch):
    module = XssTester()
    module.set_option("target", "https://t.local/search")
    module.set_option("param", "q")

    def fake_request(self, method, url, **kw):
        return make_response(200, "<html><p>nothing reflected</p></html>", url=url)

    monkeypatch.setattr(HttpClient, "request", fake_request)
    module.run()
    assert module.get_findings() == []


# ---------------------------------------------------------------------
# SQLi — baseline calibration logic
# ---------------------------------------------------------------------


def test_sqli_baseline_suppresses_noisy_page(make_response, monkeypatch):
    import redkit.modules.vuln_scan.sqli_tester as st

    monkeypatch.setattr(st, "SQLI_PAYLOADS", ["'", "1' UNION SELECT NULL --"])
    module = st.SqliTester()
    module.set_option("target", "https://t.local/noisy")
    module.set_option("param", "id")

    def fake_request(self, method, url, **kw):
        return make_response(200, "<html>docs about database error and syntax error messages</html>", url=url)

    monkeypatch.setattr(HttpClient, "request", fake_request)
    module.run()
    assert module.get_findings() == []


def test_sqli_error_based_detected_and_deduped(make_response, monkeypatch):
    import redkit.modules.vuln_scan.sqli_tester as st

    monkeypatch.setattr(st, "SQLI_PAYLOADS", ["'", "' OR '1'='1"])
    module = st.SqliTester()
    module.set_option("target", "https://t.local/vuln")
    module.set_option("param", "id")

    def fake_request(self, method, url, **kw):
        idv = unquote(_query_value(url, "id"))
        if "'" in idv:
            return make_response(200, "<html>you have an error in your sql syntax near ''</html>", url=url)
        return make_response(200, "<html>item ok</html>", url=url)

    monkeypatch.setattr(HttpClient, "request", fake_request)
    module.run()

    findings = module.get_findings()
    assert len(findings) == 1  # one per DB type
    assert findings[0].severity.value == "CRITICAL"
    assert "Error-based" in findings[0].title
    assert "MySQL" in findings[0].title


def test_sqli_time_based_confirmed_with_retest(make_response, monkeypatch):
    import redkit.modules.vuln_scan.sqli_tester as st

    monkeypatch.setattr(st, "SQLI_PAYLOADS", ["1' AND SLEEP(5) --"])
    monkeypatch.setattr(st, "TIME_THRESHOLD", 0.05)
    module = st.SqliTester()
    module.set_option("target", "https://t.local/slow")
    module.set_option("param", "id")

    def fake_request(self, method, url, **kw):
        if "SLEEP" in unquote(_query_value(url, "id")):
            time.sleep(0.12)
        return make_response(200, "ok", url=url)

    monkeypatch.setattr(HttpClient, "request", fake_request)
    module.run()

    findings = module.get_findings()
    assert len(findings) == 1
    assert findings[0].severity.value == "CRITICAL"
    assert "reproducible" in findings[0].title.lower()


def test_sqli_naturally_slow_server_not_flagged(make_response, monkeypatch):
    import redkit.modules.vuln_scan.sqli_tester as st

    monkeypatch.setattr(st, "SQLI_PAYLOADS", ["1' AND SLEEP(5) --"])
    monkeypatch.setattr(st, "TIME_THRESHOLD", 0.05)
    module = st.SqliTester()
    module.set_option("target", "https://t.local/slow_all")
    module.set_option("param", "id")

    def fake_request(self, method, url, **kw):
        # EVERY response is slow — baseline raises the threshold above it
        time.sleep(0.12)
        return make_response(200, "ok", url=url)

    monkeypatch.setattr(HttpClient, "request", fake_request)
    module.run()
    assert module.get_findings() == []


# ---------------------------------------------------------------------
# LFI
# ---------------------------------------------------------------------


def test_lfi_confirmed_with_signature(make_response, monkeypatch):
    module = LfiTester()
    module.set_option("target", "https://t.local/page")
    module.set_option("param", "file")

    def fake_request(self, method, url, **kw):
        if "../etc/passwd" in url:
            return make_response(200, "root:x:0:0:root:/root:/bin/bash\n", url=url)
        return make_response(200, "normal page", url=url)

    monkeypatch.setattr(HttpClient, "request", fake_request)
    module.run()

    findings = module.get_findings()
    assert len(findings) == 1
    assert findings[0].severity.value == "CRITICAL"
    assert "root:x:0:0" in findings[0].evidence


def test_lfi_no_false_positive_on_normal_page(make_response, monkeypatch):
    module = LfiTester()
    module.set_option("target", "https://t.local/page")
    module.set_option("param", "file")

    def fake_request(self, method, url, **kw):
        return make_response(200, "<html>totally normal page</html>", url=url)

    monkeypatch.setattr(HttpClient, "request", fake_request)
    module.run()
    assert module.get_findings() == []
