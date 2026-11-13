"""Tests for redkit.modules.auth — login brute-force and default credentials."""

from redkit.core.http_client import HttpClient
from redkit.modules.auth.default_creds import _REDIRECT_STATUSES, DefaultCreds
from redkit.modules.auth.login_bruteforce import LoginBruteforce, _mask_secret

FAILURE_PAGE = "Invalid password, try again"


def _make_login_backend(correct_user: str, correct_pass: str, make_response):
    """Return a fake HttpClient.request implementing a tiny login backend."""

    def fake_request(self, method, url, *, data=None, **kw):
        assert method == "POST"
        if data.get("user") == correct_user and data.get("pass") == correct_pass:
            return make_response(302, "", {"Location": "/home"}, url=url)
        return make_response(200, FAILURE_PAGE, url=url)

    return fake_request


# ---------------------------------------------------------------------
# Login Brute-Forcer
# ---------------------------------------------------------------------


def test_login_wordlist_skips_comments_and_blanks(tmp_path):
    wl = tmp_path / "pw.txt"
    wl.write_text("# header comment\nabc\n\n   \nxyz\n")
    assert LoginBruteforce._load_wordlist(str(wl)) == ["abc", "xyz"]


def test_login_success_via_redirect(make_response, monkeypatch, tmp_path):
    monkeypatch.setattr("redkit.modules.auth.login_bruteforce._RATE_LIMIT_DELAY", 0.0)
    wl = tmp_path / "pw.txt"
    wl.write_text("# comment\nwrong1\ns3cret\nwrong2\n")

    module = LoginBruteforce()
    module.set_option("target", "https://t.local/login")
    module.set_option("username_field", "user")
    module.set_option("password_field", "pass")
    module.set_option("username", "admin")
    module.set_option("wordlist", str(wl))
    module.set_option("failure_string", "Invalid password")
    module.set_option("threads", "1")

    monkeypatch.setattr(HttpClient, "request", _make_login_backend("admin", "s3cret", make_response))
    module.run()

    findings = module.get_findings()
    assert len(findings) == 1
    assert "s3cret" in findings[0].title
    assert findings[0].severity.value == "CRITICAL"


def test_login_failure_on_hardened_target(make_response, monkeypatch, tmp_path):
    monkeypatch.setattr("redkit.modules.auth.login_bruteforce._RATE_LIMIT_DELAY", 0.0)
    wl = tmp_path / "pw.txt"
    wl.write_text("wrong1\nwrong2\n")

    module = LoginBruteforce()
    module.set_option("target", "https://t.local/login")
    module.set_option("username_field", "user")
    module.set_option("password_field", "pass")
    module.set_option("username", "admin")
    module.set_option("wordlist", str(wl))
    module.set_option("failure_string", "Invalid password")

    monkeypatch.setattr(HttpClient, "request", _make_login_backend("admin", "not-in-list", make_response))
    module.run()
    assert module.get_findings() == []


def test_login_baseline_probe_detects_rate_limit_pages(make_response, monkeypatch, tmp_path):
    """429 responses that omit the failure string must NOT count as success."""
    monkeypatch.setattr("redkit.modules.auth.login_bruteforce._RATE_LIMIT_DELAY", 0.0)
    wl = tmp_path / "pw.txt"
    wl.write_text("pw1\npw2\n")

    module = LoginBruteforce()
    module.set_option("target", "https://t.local/login")
    module.set_option("username_field", "user")
    module.set_option("password_field", "pass")
    module.set_option("username", "admin")
    module.set_option("wordlist", str(wl))
    module.set_option("failure_string", "Invalid password")

    def fake_request(self, method, url, *, data=None, **kw):
        return make_response(429, "slow down", url=url)  # omits failure string

    monkeypatch.setattr(HttpClient, "request", fake_request)
    module.run()
    assert module.get_findings() == []


def test_mask_secret():
    assert _mask_secret("s3cret") == "s3***"
    assert _mask_secret("ab") == "***"
    assert _mask_secret("") == "***"


# ---------------------------------------------------------------------
# Default Credentials Checker
# ---------------------------------------------------------------------


def test_default_creds_detects_valid_pair(make_response, monkeypatch):
    monkeypatch.setattr("redkit.modules.auth.default_creds.time.sleep", lambda s: None)

    module = DefaultCreds()
    module.set_option("target", "https://t.local/login")
    module.set_option("username_field", "user")
    module.set_option("password_field", "pass")
    module.set_option("failure_string", "Invalid credentials")

    monkeypatch.setattr(HttpClient, "request", _make_login_backend("admin", "admin", make_response))
    module.run()

    findings = module.get_findings()
    assert len(findings) == 1
    assert "admin:admin" in findings[0].title
    assert findings[0].severity.value == "CRITICAL"


def test_default_creds_none_found_on_hardened_target(make_response, monkeypatch):
    monkeypatch.setattr("redkit.modules.auth.default_creds.time.sleep", lambda s: None)

    module = DefaultCreds()
    module.set_option("target", "https://t.local/login")
    module.set_option("username_field", "user")
    module.set_option("password_field", "pass")
    module.set_option("failure_string", "Invalid credentials")

    monkeypatch.setattr(HttpClient, "request", _make_login_backend("admin", "unguessable", make_response))
    module.run()
    assert module.get_findings() == []


def test_redirect_statuses_constant():
    assert _REDIRECT_STATUSES == (301, 302, 303, 307, 308)
