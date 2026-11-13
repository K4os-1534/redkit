"""Tests for the new recon modules — takeover, DNS records, robots, JS, Wayback."""

import dns.resolver

from redkit.core.http_client import HttpClient
from redkit.modules.recon.dns_records import DnsRecordsAuditor
from redkit.modules.recon.historical_urls import HistoricalUrls
from redkit.modules.recon.js_analyzer import JavaScriptAnalyzer
from redkit.modules.recon.robots_sitemap import RobotsSitemapHarvester
from redkit.modules.recon.subdomain_takeover import SubdomainTakeover

SOFT_404 = "soft-404 page with a constant body size"


# ---------------------------------------------------------------------
# Subdomain Takeover
# ---------------------------------------------------------------------


class _TakeoverResolver:
    """CNAMEs everything to S3; A records exist except for 'dangling.test'."""

    def __init__(self):
        self.timeout = None
        self.lifetime = None

    def resolve(self, fqdn, rtype):
        fqdn = fqdn.lower()
        if rtype == "CNAME":

            class _R:
                target = "dangling-bucket.s3.amazonaws.com."

            return [_R()]
        if fqdn.startswith("dangling."):
            raise dns.resolver.NXDOMAIN()

        class _A:
            address = "1.2.3.4"

        return [_A()]


def _takeover_http(make_response, body):
    def fake(self, method, url, **kw):
        return make_response(200, body, url=url)

    return fake


def test_takeover_confirmed_with_vendor_fingerprint(make_response, monkeypatch):
    monkeypatch.setattr("dns.resolver.Resolver", _TakeoverResolver)
    module = SubdomainTakeover()
    module.set_option("target", "https://victim.test")
    monkeypatch.setattr(
        HttpClient,
        "request",
        _takeover_http(make_response, "NoSuchBucket. The specified bucket does not exist."),
    )
    module.run()
    findings = module.get_findings()
    assert len(findings) == 1
    assert "AWS S3" in findings[0].title
    assert findings[0].cvss == 8.2


def test_takeover_generic_404_not_reported(make_response, monkeypatch):
    """A CNAME plus an ordinary 404 page must NOT fire (FP guard)."""
    monkeypatch.setattr("dns.resolver.Resolver", _TakeoverResolver)
    module = SubdomainTakeover()
    module.set_option("target", "https://victim.test")
    monkeypatch.setattr(HttpClient, "request", _takeover_http(make_response, "<h1>404 Not Found</h1>"))
    module.run()
    assert module.get_findings() == []


def test_takeover_cname_without_fingerprint_not_reported(make_response, monkeypatch):
    monkeypatch.setattr("dns.resolver.Resolver", _TakeoverResolver)
    module = SubdomainTakeover()
    module.set_option("target", "https://victim.test")
    monkeypatch.setattr(HttpClient, "request", _takeover_http(make_response, "Welcome to our site!"))
    module.run()
    assert module.get_findings() == []


# ---------------------------------------------------------------------
# DNS Records Auditor
# ---------------------------------------------------------------------


class _MailResolver:
    """A + MX + SPF present, no DMARC."""

    def __init__(self):
        self.timeout = None
        self.lifetime = None

    def resolve(self, fqdn, rtype):
        if fqdn.startswith("_dmarc."):
            raise dns.resolver.NXDOMAIN()
        if rtype == "A":

            class _A:
                address = "1.2.3.4"

            return [_A()]
        if rtype == "MX":

            class _M:
                preference = 10
                exchange = "mail.example.com."

            return [_M()]
        if rtype == "TXT":

            class _T:
                def __str__(self):
                    return '"v=spf1 -all"'

            return [_T()]
        raise dns.resolver.NoAnswer()


def test_dns_records_mail_without_dmarc(make_response, monkeypatch):
    monkeypatch.setattr("dns.resolver.Resolver", _MailResolver)
    module = DnsRecordsAuditor()
    module.set_option("target", "example.com")
    module.run()
    findings = module.get_findings()
    assert any(f.title.startswith("A records") for f in findings)
    assert any(f.title.startswith("MX records") for f in findings)
    assert any("No DMARC" in f.title for f in findings)
    assert not any("No SPF" in f.title for f in findings)  # SPF exists
    assert not any(f.severity.value == "MEDIUM" and "AXFR" in f.title for f in findings)


def test_dns_records_web_host_no_mail_findings(monkeypatch):
    """No MX → no SPF/DMARC findings (the FP guard for web hostnames)."""

    class _WebResolver(_MailResolver):
        def resolve(self, fqdn, rtype):
            if rtype == "MX":
                raise dns.resolver.NoAnswer()
            return super().resolve(fqdn, rtype)

    monkeypatch.setattr("dns.resolver.Resolver", _WebResolver)
    module = DnsRecordsAuditor()
    module.set_option("target", "example.com")
    module.run()
    assert not any("SPF" in f.title or "DMARC" in f.title for f in module.get_findings())


# ---------------------------------------------------------------------
# robots.txt & Sitemap Harvester
# ---------------------------------------------------------------------


def test_robots_harvests_disallow_and_sitemap(make_response, monkeypatch):
    module = RobotsSitemapHarvester()
    module.set_option("target", "https://t.local")

    def fake(self, method, url, **kw):
        if url.endswith("/robots.txt"):
            return make_response(
                200,
                "User-agent: *\nDisallow: /admin\nDisallow: /internal\nSitemap: https://t.local/sitemap.xml\n",
                url=url,
            )
        if url.endswith("/sitemap.xml"):
            return make_response(
                200,
                "<urlset><url><loc>https://t.local/secret</loc></url><url><loc>https://t.local/old</loc></url></urlset>",
                url=url,
            )
        return make_response(404, "nope", url=url)

    monkeypatch.setattr(HttpClient, "request", fake)
    module.run()
    findings = module.get_findings()
    assert len(findings) == 2
    assert any("robots.txt found" in f.title and "/admin" in f.evidence for f in findings)
    assert any("sitemap.xml found" in f.title and "/secret" in f.evidence for f in findings)


def test_robots_soft404_spa_ignored(make_response, monkeypatch):
    """SPA soft-404 (200 + HTML without directives) must NOT fire."""
    module = RobotsSitemapHarvester()
    module.set_option("target", "https://t.local")
    monkeypatch.setattr(
        HttpClient,
        "request",
        lambda self, m, url, **kw: make_response(200, "<html><body>SPA index</body></html>", url=url),
    )
    module.run()
    assert module.get_findings() == []


# ---------------------------------------------------------------------
# JavaScript Analyzer
# ---------------------------------------------------------------------


def test_js_analyzer_finds_key_internal_and_map(make_response, monkeypatch):
    module = JavaScriptAnalyzer()
    module.set_option("target", "https://t.local")
    app_js = (
        'var key="AKIAIOSFODNN7EXAMPLE";'
        'var api="http://localhost:3000/admin";'
        "//# sourceMappingURL=/app.js.map"
    )

    def fake(self, method, url, **kw):
        if url == "https://t.local":
            return make_response(200, '<script src="/app.js"></script>', url=url)
        if url.endswith("/app.js"):
            return make_response(200, app_js, url=url)
        if url.endswith("/app.js.map"):
            return make_response(200, '{"sources":["app.ts"]}', url=url)
        return make_response(404, "nope", url=url)

    monkeypatch.setattr(HttpClient, "request", fake)
    module.run()
    findings = module.get_findings()
    assert any("AWS Access Key" in f.title and f.severity.value == "HIGH" for f in findings)
    assert any("Internal host" in f.title for f in findings)
    assert any("Source map exposed" in f.title and f.severity.value == "LOW" for f in findings)


def test_js_analyzer_clean_bundle_no_findings(make_response, monkeypatch):
    module = JavaScriptAnalyzer()
    module.set_option("target", "https://t.local")
    monkeypatch.setattr(
        HttpClient,
        "request",
        lambda self, m, url, **kw: make_response(
            200,
            '<script src="/app.js"></script>' if url == "https://t.local" else "var x=1;",
            url=url,
        ),
    )
    module.run()
    assert module.get_findings() == []


# ---------------------------------------------------------------------
# Historical URLs (Wayback)
# ---------------------------------------------------------------------


def test_wayback_aggregates_into_one_finding(make_response, monkeypatch):
    module = HistoricalUrls()
    module.set_option("target", "https://t.local")
    monkeypatch.setattr(
        HttpClient,
        "request",
        lambda self, m, url, **kw: make_response(
            200, '[["original"],["https://t.local/old1"],["https://t.local/old2"]]', url=url
        ),
    )
    module.run()
    findings = module.get_findings()
    assert len(findings) == 1
    assert "2 historical URLs" in findings[0].title
    assert "/old1" in findings[0].evidence


def test_wayback_unreachable_degrades_gracefully(monkeypatch):
    module = HistoricalUrls()
    module.set_option("target", "https://t.local")

    def fail(*a, **kw):
        raise ConnectionError("archive down")

    monkeypatch.setattr(HttpClient, "request", fail)
    module.run()  # must not raise
    assert module.get_findings() == []
