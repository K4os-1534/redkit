"""Tests for the new auth modules — user enumeration and HTTP Basic brute-force."""

from redkit.core.http_client import HttpClient
from redkit.modules.auth.basic_auth_bruteforce import BasicAuthBruteforcer
from redkit.modules.auth.user_enumerator import UserEnumerator

# ---------------------------------------------------------------------
# Username Enumerator
# ---------------------------------------------------------------------


def test_user_enum_message_difference_is_medium(make_response, monkeypatch):
    module = UserEnumerator()
    module.set_option("target", "https://t.local/login")
    module.set_option("known_username", "admin")

    def fake(self, method, url, *, data=None, **kw):
        user = (data or {}).get("username", "")
        # Existing user: password-specific message; unknown user: user-specific message
        body = "Incorrect password provided." if user == "admin" else "Unknown username."
        return make_response(200, body, url=url)

    monkeypatch.setattr(HttpClient, "request", fake)
    module.run()
    findings = module.get_findings()
    assert len(findings) == 1
    assert findings[0].severity.value == "MEDIUM"
    assert "error messages" in findings[0].title


def test_user_enum_identical_responses_no_finding(make_response, monkeypatch):
    module = UserEnumerator()
    module.set_option("target", "https://t.local/login")
    module.set_option("known_username", "admin")
    monkeypatch.setattr(
        HttpClient,
        "request",
        lambda self, m, url, *, data=None, **kw: make_response(200, "Invalid credentials.", url=url),
    )
    module.run()
    assert module.get_findings() == []


def test_user_enum_timing_only_is_info(make_response, monkeypatch):
    import time

    module = UserEnumerator()
    module.set_option("target", "https://t.local/login")
    module.set_option("known_username", "admin")

    def fake(self, method, url, *, data=None, **kw):
        if (data or {}).get("username") == "admin":
            time.sleep(0.4)  # existing user triggers a slow DB lookup
        return make_response(200, "Invalid credentials.", url=url)

    monkeypatch.setattr(HttpClient, "request", fake)
    module.run()
    findings = module.get_findings()
    assert len(findings) == 1
    assert findings[0].severity.value == "INFO"
    assert "timing" in findings[0].title


# ---------------------------------------------------------------------
# HTTP Basic Brute-Forcer
# ---------------------------------------------------------------------


def test_basic_auth_success_found(make_response, monkeypatch, tmp_path):
    import base64

    monkeypatch.setattr("redkit.modules.auth.basic_auth_bruteforce._RATE_LIMIT_DELAY", 0.0)
    wl = tmp_path / "pw.txt"
    wl.write_text("# comment\nwrong1\nletmein\nwrong2\n")

    module = BasicAuthBruteforcer()
    module.set_option("target", "https://t.local/admin")
    module.set_option("username", "admin")
    module.set_option("wordlist", str(wl))
    module.set_option("threads", "1")

    def fake(self, method, url, *, headers=None, **kw):
        auth = (headers or {}).get("Authorization", "")
        if auth.startswith("Basic "):
            creds = base64.b64decode(auth[6:]).decode()
            if creds == "admin:letmein":
                return make_response(200, "admin panel", url=url)
        return make_response(401, "denied", {"WWW-Authenticate": 'Basic realm="admin"'}, url=url)

    monkeypatch.setattr(HttpClient, "request", fake)
    module.run()
    findings = module.get_findings()
    assert len(findings) == 1
    assert "letmein" in findings[0].title
    assert findings[0].cvss == 9.8


def test_basic_auth_gate_aborts_on_non_basic_target(make_response, monkeypatch):
    """A target that never returns 401 must abort with zero findings."""
    module = BasicAuthBruteforcer()
    module.set_option("target", "https://t.local/admin")
    module.set_option("username", "admin")
    monkeypatch.setattr(
        HttpClient,
        "request",
        lambda self, m, url, **kw: make_response(200, "public page", url=url),
    )
    module.run()
    assert module.get_findings() == []


def test_basic_auth_wordlist_skips_comments(tmp_path):
    wl = tmp_path / "pw.txt"
    wl.write_text("# header\nabc\n\nxyz\n")
    assert BasicAuthBruteforcer._load_wordlist(str(wl)) == ["abc", "xyz"]
