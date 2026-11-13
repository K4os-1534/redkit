"""Tests for misconfig modules — headers, cookies, CORS, sensitive files, docs, GraphQL."""

from redkit.core.http_client import HttpClient
from redkit.modules.misconfig.api_docs import ApiDocsExposure
from redkit.modules.misconfig.cookie_auditor import CookieAuditor
from redkit.modules.misconfig.cors_auditor import ATTACKER_ORIGIN, CorsAuditor
from redkit.modules.misconfig.graphql_introspection import GraphqlIntrospection
from redkit.modules.misconfig.security_headers import SecurityHeadersAuditor
from redkit.modules.misconfig.sensitive_files import SensitiveFileDisclosure

SOFT_404 = "soft-404 page with a constant body size"


def _first(findings):
    return findings[0]


# ---------------------------------------------------------------------
# Security Headers Auditor
# ---------------------------------------------------------------------


def test_headers_all_missing(make_response, monkeypatch):
    module = SecurityHeadersAuditor()
    module.set_option("target", "https://t.local/")

    monkeypatch.setattr(
        HttpClient, "request", lambda self, m, url, **kw: make_response(200, "<html>hi</html>", url=url)
    )
    module.run()
    titles = [f.title for f in module.get_findings()]
    assert any("Content-Security-Policy" in t for t in titles)
    assert any("HSTS" in t for t in titles)
    assert any("X-Frame-Options" in t for t in titles)
    assert len(module.get_findings()) == 6


def test_headers_all_present_no_findings(make_response, monkeypatch):
    module = SecurityHeadersAuditor()
    module.set_option("target", "https://t.local/")
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
    }
    monkeypatch.setattr(
        HttpClient,
        "request",
        lambda self, m, url, **kw: make_response(200, "<html>hi</html>", headers, url=url),
    )
    module.run()
    assert module.get_findings() == []


def test_headers_hsts_too_short_is_low(make_response, monkeypatch):
    module = SecurityHeadersAuditor()
    module.set_option("target", "https://t.local/")
    headers = {"Content-Security-Policy": "default-src 'self'", "Strict-Transport-Security": "max-age=600"}
    # fill the rest so only the weak HSTS fires
    headers["X-Frame-Options"] = "DENY"
    headers["X-Content-Type-Options"] = "nosniff"
    headers["Referrer-Policy"] = "no-referrer"
    headers["Permissions-Policy"] = "geolocation=()"
    monkeypatch.setattr(
        HttpClient, "request", lambda self, m, url, **kw: make_response(200, "x", headers, url=url)
    )
    module.run()
    findings = module.get_findings()
    assert len(findings) == 1
    assert findings[0].title == "Weak HSTS max-age"
    assert findings[0].severity.value == "LOW"


def test_headers_http_target_skips_hsts(make_response, monkeypatch):
    module = SecurityHeadersAuditor()
    module.set_option("target", "http://t.local/")
    monkeypatch.setattr(HttpClient, "request", lambda self, m, url, **kw: make_response(200, "x", url=url))
    module.run()
    assert not any("HSTS" in f.title for f in module.get_findings())


# ---------------------------------------------------------------------
# Cookie Auditor
# ---------------------------------------------------------------------


def test_cookie_session_without_flags_is_medium(make_response, monkeypatch):
    module = CookieAuditor()
    module.set_option("target", "https://t.local/login")
    monkeypatch.setattr(
        HttpClient,
        "request",
        lambda self, m, url, **kw: make_response(
            200, "x", {"Set-Cookie": "sessionid=abc123; Path=/"}, url=url
        ),
    )
    module.run()
    findings = module.get_findings()
    assert len(findings) == 1
    assert findings[0].severity.value == "MEDIUM"
    assert "Secure" in findings[0].title and "HttpOnly" in findings[0].title


def test_cookie_with_all_flags_no_findings(make_response, monkeypatch):
    module = CookieAuditor()
    module.set_option("target", "https://t.local/login")
    monkeypatch.setattr(
        HttpClient,
        "request",
        lambda self, m, url, **kw: make_response(
            200, "x", {"Set-Cookie": "sessionid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"}, url=url
        ),
    )
    module.run()
    assert module.get_findings() == []


def test_cookie_non_session_low(make_response, monkeypatch):
    module = CookieAuditor()
    module.set_option("target", "https://t.local/")
    monkeypatch.setattr(
        HttpClient,
        "request",
        lambda self, m, url, **kw: make_response(200, "x", {"Set-Cookie": "theme=dark; Path=/"}, url=url),
    )
    module.run()
    findings = module.get_findings()
    assert len(findings) == 1
    assert findings[0].severity.value == "LOW"
    assert "SameSite" in findings[0].title


# ---------------------------------------------------------------------
# CORS Tester
# ---------------------------------------------------------------------


def test_cors_reflection_with_credentials_high(make_response, monkeypatch):
    module = CorsAuditor()
    module.set_option("target", "https://t.local/api/user")

    def fake(self, method, url, *, headers=None, **kw):
        origin = (headers or {}).get("Origin", "")
        if origin == ATTACKER_ORIGIN:
            return make_response(
                200,
                "{}",
                {"Access-Control-Allow-Origin": ATTACKER_ORIGIN, "Access-Control-Allow-Credentials": "true"},
                url=url,
            )
        return make_response(200, "{}", url=url)

    monkeypatch.setattr(HttpClient, "request", fake)
    module.run()
    findings = module.get_findings()
    assert len(findings) == 1
    assert findings[0].severity.value == "HIGH"
    assert "credentials" in findings[0].title


def test_cors_reflection_without_credentials_medium(make_response, monkeypatch):
    module = CorsAuditor()
    module.set_option("target", "https://t.local/api/user")

    def fake(self, method, url, *, headers=None, **kw):
        origin = (headers or {}).get("Origin", "")
        acao = {ATTACKER_ORIGIN: ATTACKER_ORIGIN, "null": "null"}.get(origin, "")
        hdrs = {"Access-Control-Allow-Origin": acao} if acao else {}
        return make_response(200, "{}", hdrs, url=url)

    monkeypatch.setattr(HttpClient, "request", fake)
    module.run()
    findings = module.get_findings()
    assert {f.severity.value for f in findings} == {"MEDIUM"}
    assert any("null" in f.title for f in findings)


def test_cors_benign_policy_no_findings(make_response, monkeypatch):
    module = CorsAuditor()
    module.set_option("target", "https://t.local/api/user")
    monkeypatch.setattr(
        HttpClient,
        "request",
        lambda self, m, url, **kw: make_response(
            200, "{}", {"Access-Control-Allow-Origin": "https://trusted.example.com"}, url=url
        ),
    )
    module.run()
    assert module.get_findings() == []


# ---------------------------------------------------------------------
# Sensitive File Disclosure
# ---------------------------------------------------------------------


def test_sensitive_files_git_and_env_detected(make_response, monkeypatch):
    module = SensitiveFileDisclosure()
    module.set_option("target", "https://t.local")
    module.set_option("threads", "1")

    def fake(self, method, url, **kw):
        if url.endswith("/.git/HEAD"):
            return make_response(200, "ref: refs/heads/main\n", url=url)
        if url.endswith("/.env"):
            return make_response(200, "DB_PASSWORD=secret\n", url=url)
        return make_response(404, "nope", url=url)

    monkeypatch.setattr(HttpClient, "request", fake)
    module.run()
    findings = module.get_findings()
    assert len(findings) == 2
    assert all(f.severity.value == "HIGH" for f in findings)
    assert any("/.git/HEAD" in f.title for f in findings)
    assert findings[0].cvss == 7.5


def test_sensitive_files_soft404_and_wrong_content_ignored(make_response, monkeypatch):
    module = SensitiveFileDisclosure()
    module.set_option("target", "https://t.local")
    module.set_option("threads", "1")

    # Every path returns the SAME soft-404 body — even /.git/HEAD with 200
    monkeypatch.setattr(
        HttpClient,
        "request",
        lambda self, m, url, **kw: make_response(200, SOFT_404, url=url),
    )
    module.run()
    assert module.get_findings() == []


# ---------------------------------------------------------------------
# API Docs Exposure
# ---------------------------------------------------------------------


def test_api_docs_swagger_detected(make_response, monkeypatch):
    module = ApiDocsExposure()
    module.set_option("target", "https://t.local")
    module.set_option("threads", "1")
    monkeypatch.setattr(
        HttpClient,
        "request",
        lambda self, m, url, **kw: (
            make_response(200, '{"openapi": "3.0.0", "info": {}}', url=url)
            if url.endswith("/swagger.json")
            else make_response(404, "nope", url=url)
        ),
    )
    module.run()
    findings = module.get_findings()
    # Both /swagger.json and /api-docs/swagger.json are exposed — two URLs.
    assert len(findings) == 2
    assert all("/swagger.json" in f.title for f in findings)
    assert all(f.cvss == 5.3 for f in findings)


def test_api_docs_soft404_filtered(make_response, monkeypatch):
    module = ApiDocsExposure()
    module.set_option("target", "https://t.local")
    module.set_option("threads", "1")
    monkeypatch.setattr(
        HttpClient,
        "request",
        lambda self, m, url, **kw: make_response(200, SOFT_404, url=url),
    )
    module.run()
    assert module.get_findings() == []


# ---------------------------------------------------------------------
# GraphQL Introspection
# ---------------------------------------------------------------------


def test_graphql_introspection_enabled(make_response, monkeypatch):
    module = GraphqlIntrospection()
    module.set_option("target", "https://t.local")

    def fake(self, method, url, *, data=None, **kw):
        assert method == "POST"
        if url == "https://t.local/graphql":
            body = '{"data":{"__schema":{"queryType":{"name":"Query"}}}}'
            return make_response(200, body, url=url)
        return make_response(404, "nope", url=url)

    monkeypatch.setattr(HttpClient, "request", fake)
    module.run()
    findings = module.get_findings()
    assert len(findings) == 1
    assert "introspection enabled" in findings[0].title
    assert findings[0].cvss == 5.3


def test_graphql_endpoint_hardened_is_info(make_response, monkeypatch):
    module = GraphqlIntrospection()
    module.set_option("target", "https://t.local")
    monkeypatch.setattr(
        HttpClient,
        "request",
        lambda self, m, url, *, data=None, **kw: (
            make_response(200, "GraphQL endpoint - introspection is disabled", url=url)
            if url == "https://t.local/graphql"
            else make_response(404, "nope", url=url)
        ),
    )
    module.run()
    findings = module.get_findings()
    assert len(findings) == 1
    assert findings[0].severity.value == "INFO"
    assert "introspection disabled" in findings[0].title
