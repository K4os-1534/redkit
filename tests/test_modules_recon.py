"""Tests for redkit.modules.recon — dir brute-force, subdomain enum, tech fingerprint."""

from urllib.parse import urlparse

import dns.resolver

from redkit.core.http_client import HttpClient
from redkit.modules.recon.dir_bruteforce import DirBruteforce
from redkit.modules.recon.subdomain_enum import SubdomainEnum
from redkit.modules.recon.tech_fingerprint import TechFingerprint

# ---------------------------------------------------------------------
# Directory Brute-Forcer
# ---------------------------------------------------------------------


def test_dir_bruteforce_filters_soft_404(make_response, monkeypatch, tmp_path):
    wl = tmp_path / "dirs.txt"
    wl.write_text("# comment\nadmin\nnonexistent1\nnonexistent2\n")

    module = DirBruteforce()
    module.set_option("target", "https://t.local/site")
    module.set_option("wordlist", str(wl))
    module.set_option("extensions", "")

    soft_404 = "soft-404 page with a constant body size"

    def fake_request(self, method, url, **kw):
        path = urlparse(url).path
        if path == "/site/admin":
            return make_response(200, "secret admin panel", url=url)
        return make_response(200, soft_404, url=url)

    monkeypatch.setattr(HttpClient, "request", fake_request)
    module.run()

    findings = module.get_findings()
    assert len(findings) == 1
    assert "/site/admin" in findings[0].title
    assert findings[0].severity.value == "MEDIUM"


def test_dir_bruteforce_skips_real_404(make_response, monkeypatch, tmp_path):
    wl = tmp_path / "dirs.txt"
    wl.write_text("admin\nghost\n")

    module = DirBruteforce()
    module.set_option("target", "https://t.local")
    module.set_option("wordlist", str(wl))
    module.set_option("extensions", "")

    def fake_request(self, method, url, **kw):
        path = urlparse(url).path
        if path == "/admin":
            return make_response(200, "admin panel", url=url)
        return make_response(404, "nope", url=url)

    monkeypatch.setattr(HttpClient, "request", fake_request)
    module.run()
    assert [f.title for f in module.get_findings()] == ["[200] https://t.local/admin"]


def test_dir_bruteforce_build_urls():
    urls = DirBruteforce._build_urls("https://t.local", ["admin"], ["php", "html"])
    assert urls == [
        "https://t.local/admin",
        "https://t.local/admin.php",
        "https://t.local/admin.html",
    ]


def test_dir_bruteforce_wordlist_comments_skipped(tmp_path):
    wl = tmp_path / "dirs.txt"
    wl.write_text("# header\nadmin\n\nghost\n")
    assert DirBruteforce._load_wordlist(str(wl)) == ["admin", "ghost"]


# ---------------------------------------------------------------------
# Subdomain Enumerator
# ---------------------------------------------------------------------


class _FakeAnswer:
    def __init__(self, ip):
        self.address = ip


class _FakeResolver:
    def __init__(self):
        self.timeout = None
        self.lifetime = None

    def resolve(self, fqdn, rtype):
        if fqdn.startswith("www."):
            return [_FakeAnswer("1.2.3.4")]
        if fqdn.startswith("mail."):
            return [_FakeAnswer("5.6.7.8"), _FakeAnswer("5.6.7.9")]
        raise dns.resolver.NXDOMAIN()


def test_subdomain_enum_reports_resolved(make_response, monkeypatch, tmp_path):
    wl = tmp_path / "subs.txt"
    wl.write_text("# c\nwww\nmail\nnothing\n")

    module = SubdomainEnum()
    module.set_option("target", "example.com")
    module.set_option("wordlist", str(wl))

    monkeypatch.setattr("dns.resolver.Resolver", _FakeResolver)
    module.run()

    findings = module.get_findings()
    assert len(findings) == 2
    titles = " | ".join(f.title for f in findings)
    assert "www.example.com" in titles
    assert "mail.example.com" in titles
    mail_finding = next(f for f in findings if "mail." in f.title)
    assert "5.6.7.8" in mail_finding.detail


def test_subdomain_enum_strips_scheme():
    assert SubdomainEnum._strip_scheme("https://example.com/path") == "example.com"


# ---------------------------------------------------------------------
# Technology Fingerprinter
# ---------------------------------------------------------------------


def test_tech_fingerprint_detects_from_headers_and_body(make_response, monkeypatch):
    module = TechFingerprint()
    module.set_option("target", "https://t.local/")

    body = (
        "<html><meta name='generator' content='WordPress 6.0'>"
        "<script src='/jquery-3.6.0.min.js'></script></html>"
    )

    def fake_request(self, method, url, **kw):
        return make_response(200, body, {"Server": "nginx", "X-Powered-By": "PHP/8.1.0"}, url=url)

    monkeypatch.setattr(HttpClient, "request", fake_request)
    module.run()

    titles = [f.title for f in module.get_findings()]
    assert any("Nginx" in t for t in titles)
    assert any("PHP" in t for t in titles)
    assert any("WordPress CMS" in t for t in titles)
    assert any("jQuery" in t for t in titles)


def test_tech_fingerprint_no_crash_on_error(make_response, monkeypatch):
    module = TechFingerprint()
    module.set_option("target", "https://t.local/")

    def fake_request(self, method, url, **kw):
        raise ConnectionError("unreachable")

    monkeypatch.setattr(HttpClient, "request", fake_request)
    module.run()  # must not raise
    assert module.get_findings() == []
