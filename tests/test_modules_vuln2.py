"""Tests for the new vuln_scan modules — SSTI, open redirect, cmd, CRLF, XXE, SSRF."""

import time
from urllib.parse import unquote

import redkit.modules.vuln_scan.cmd_injection_tester as cmd_mod
from redkit.core.http_client import HttpClient
from redkit.modules.vuln_scan.cmd_injection_tester import CmdInjectionTester
from redkit.modules.vuln_scan.crlf_tester import CrlfTester
from redkit.modules.vuln_scan.open_redirect_tester import REDIRECT_HOST, OpenRedirectTester
from redkit.modules.vuln_scan.ssrf_tester import SsrfTester
from redkit.modules.vuln_scan.ssti_tester import SstiTester
from redkit.modules.vuln_scan.xxe_tester import XxeTester


def _q(url: str, key: str) -> str:
    from urllib.parse import parse_qs, urlparse

    return (parse_qs(urlparse(url).query).get(key) or [""])[0]


# ---------------------------------------------------------------------
# SSTI
# ---------------------------------------------------------------------


def test_ssti_confirmed_on_computed_marker(make_response, monkeypatch):
    module = SstiTester()
    module.set_option("target", "https://t.local/hello")
    module.set_option("param", "name")

    def fake(self, method, url, **kw):
        value = _q(url, "name")
        # Vulnerable: the template engine *computes* the marker payload
        if "{{1337*1337}}" in value:
            value = value.replace("{{1337*1337}}", "1787569")
        return make_response(200, f"<h1>{value}</h1>", url=url)

    monkeypatch.setattr(HttpClient, "request", fake)
    module.run()
    findings = module.get_findings()
    assert len(findings) == 1
    assert findings[0].severity.value == "CRITICAL"
    assert "1787569" in findings[0].evidence


def test_ssti_verbatim_reflection_not_reported(make_response, monkeypatch):
    """A server that merely echoes the payload (no evaluation) must NOT fire."""
    module = SstiTester()
    module.set_option("target", "https://t.local/hello")
    module.set_option("param", "name")
    monkeypatch.setattr(
        HttpClient,
        "request",
        lambda self, m, url, **kw: make_response(200, f"<h1>{unquote(_q(url, 'name'))}</h1>", url=url),
    )
    module.run()
    assert module.get_findings() == []


# ---------------------------------------------------------------------
# Open Redirect
# ---------------------------------------------------------------------


def test_open_redirect_confirmed_via_location(make_response, monkeypatch):
    module = OpenRedirectTester()
    module.set_option("target", "https://t.local/redirect")
    module.set_option("param", "to")

    def fake(self, method, url, **kw):
        value = _q(url, "to")
        if REDIRECT_HOST in unquote(value):
            return make_response(302, "", {"Location": f"https://{REDIRECT_HOST}/path"}, url=url)
        return make_response(302, "", {"Location": "/home"}, url=url)

    monkeypatch.setattr(HttpClient, "request", fake)
    module.run()
    findings = module.get_findings()
    assert len(findings) == 1
    assert findings[0].severity.value == "HIGH"
    assert findings[0].cvss == 6.1


def test_open_redirect_same_origin_not_reported(make_response, monkeypatch):
    module = OpenRedirectTester()
    module.set_option("target", "https://t.local/redirect")
    module.set_option("param", "to")
    monkeypatch.setattr(
        HttpClient,
        "request",
        lambda self, m, url, **kw: make_response(302, "", {"Location": "/home"}, url=url),
    )
    module.run()
    assert module.get_findings() == []


# ---------------------------------------------------------------------
# Command Injection (time-based)
# ---------------------------------------------------------------------


def test_cmd_injection_confirmed_and_retested(make_response, monkeypatch):
    monkeypatch.setattr(cmd_mod, "TIME_THRESHOLD", 0.05)
    module = CmdInjectionTester()
    module.set_option("target", "https://t.local/ping")
    module.set_option("param", "host")

    def fake(self, method, url, **kw):
        if "sleep" in unquote(_q(url, "host")):
            time.sleep(0.12)
        return make_response(200, "ok", url=url)

    monkeypatch.setattr(HttpClient, "request", fake)
    module.run()
    findings = module.get_findings()
    assert len(findings) == 1
    assert findings[0].severity.value == "CRITICAL"
    assert findings[0].cvss == 9.8


def test_cmd_injection_slow_server_not_flagged(make_response, monkeypatch):
    monkeypatch.setattr(cmd_mod, "TIME_THRESHOLD", 0.05)
    module = CmdInjectionTester()
    module.set_option("target", "https://t.local/ping")
    module.set_option("param", "host")

    def fake(self, method, url, **kw):
        time.sleep(0.12)  # EVERY response slow — baseline raises threshold
        return make_response(200, "ok", url=url)

    monkeypatch.setattr(HttpClient, "request", fake)
    module.run()
    assert module.get_findings() == []


# ---------------------------------------------------------------------
# CRLF
# ---------------------------------------------------------------------


def test_crlf_confirmed_via_injected_header(make_response, monkeypatch):
    module = CrlfTester()
    module.set_option("target", "https://t.local/page")
    module.set_option("param", "path")

    def fake(self, method, url, **kw):
        if "x-redkit-probe" in unquote(url).lower():
            return make_response(200, "page", {"X-RedKit-Probe": "crlf-confirmed"}, url=url)
        return make_response(200, "page", url=url)

    monkeypatch.setattr(HttpClient, "request", fake)
    module.run()
    findings = module.get_findings()
    assert len(findings) == 1
    assert findings[0].severity.value == "MEDIUM"


def test_crlf_no_injection_no_finding(make_response, monkeypatch):
    module = CrlfTester()
    module.set_option("target", "https://t.local/page")
    module.set_option("param", "path")
    monkeypatch.setattr(
        HttpClient,
        "request",
        lambda self, m, url, **kw: make_response(200, "page", url=url),
    )
    module.run()
    assert module.get_findings() == []


# ---------------------------------------------------------------------
# XXE
# ---------------------------------------------------------------------


def test_xxe_confirmed_via_file_signature(make_response, monkeypatch):
    module = XxeTester()
    module.set_option("target", "https://t.local/api/xml")
    sent = {}

    def fake(self, method, url, *, data=None, headers=None, **kw):
        sent["body"] = data
        sent["ct"] = (headers or {}).get("Content-Type", "")
        return make_response(200, "root:x:0:0:root:/root:/bin/bash\n", url=url)

    monkeypatch.setattr(HttpClient, "request", fake)
    module.run()
    findings = module.get_findings()
    assert len(findings) == 1
    assert findings[0].severity.value == "CRITICAL"
    assert sent["body"].startswith("<?xml")
    assert "<!DOCTYPE" in sent["body"] and "&xxe;" in sent["body"]
    assert sent["ct"] == "application/xml"


def test_xxe_parser_rejects_no_finding(make_response, monkeypatch):
    module = XxeTester()
    module.set_option("target", "https://t.local/api/xml")
    monkeypatch.setattr(
        HttpClient,
        "request",
        lambda self, m, url, *, data=None, **kw: make_response(400, "XML parse error", url=url),
    )
    module.run()
    assert module.get_findings() == []


# ---------------------------------------------------------------------
# SSRF
# ---------------------------------------------------------------------


def test_ssrf_metadata_confirmed(make_response, monkeypatch):
    module = SsrfTester()
    module.set_option("target", "https://t.local/fetch")
    module.set_option("param", "url")

    def fake(self, method, url, **kw):
        if "169.254.169.254" in unquote(url):
            return make_response(200, "ami-id\nami-12345\ninstance-id\ni-abc123\n", url=url)
        return make_response(200, '{"status":"ok"}', url=url)

    monkeypatch.setattr(HttpClient, "request", fake)
    module.run()
    findings = module.get_findings()
    assert len(findings) == 1
    assert findings[0].severity.value == "CRITICAL"
    assert "AWS" in findings[0].title


def test_ssrf_reflection_only_not_reported(make_response, monkeypatch):
    """A server that only echoes the probe URL back must NOT fire."""
    module = SsrfTester()
    module.set_option("target", "https://t.local/fetch")
    module.set_option("param", "url")
    monkeypatch.setattr(
        HttpClient,
        "request",
        lambda self, m, url, **kw: make_response(200, f"requested: {unquote(_q(url, 'url'))}", url=url),
    )
    module.run()
    assert module.get_findings() == []
