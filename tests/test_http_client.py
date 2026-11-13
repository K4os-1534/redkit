"""Tests for redkit.core.http_client — scope, redirects, rate limit, retries."""

import pytest
import requests

from redkit.core.http_client import HttpClient, HttpClientConfig, OutOfScopeError


def build_client(scope=None, **overrides):
    params = {"user_agent": "TestUA/1.0", "timeout": 7.5, "verify_ssl": False}
    params.update(overrides)
    return HttpClient(HttpClientConfig(**params), scope=scope)


def patch_send(monkeypatch, client, responder):
    """Replace the client's raw send with a scripted responder.

    responder(method, url, data, headers) -> requests.Response.
    Returns the list of captured calls.
    """
    calls = []

    def fake_send_raw(method, url, *, data, params, headers, timeout, verify):
        calls.append(
            {
                "method": method,
                "url": url,
                "data": data,
                "headers": headers,
                "timeout": timeout,
                "verify": verify,
            }
        )
        return responder(method, url, data, headers)

    monkeypatch.setattr(client, "_send_raw", fake_send_raw)
    return calls


# ---------------------------------------------------------------------
# Defaults and session configuration
# ---------------------------------------------------------------------


def test_defaults_applied(make_response, monkeypatch):
    client = build_client()
    calls = patch_send(monkeypatch, client, lambda m, u, d, h: make_response(url=u))
    resp = client.get("https://test.local/x")
    assert resp.status_code == 200
    assert calls[0]["timeout"] == 7.5
    assert calls[0]["verify"] is False


def test_per_request_overrides(make_response, monkeypatch):
    client = build_client()
    calls = patch_send(monkeypatch, client, lambda m, u, d, h: make_response(url=u))
    client.get("https://test.local/x", timeout=1.25, verify=True, allow_redirects=False)
    assert calls[0]["timeout"] == 1.25
    assert calls[0]["verify"] is True


def test_session_configuration():
    client = build_client(
        extra_headers={"X-Test": "1"},
        cookies={"sid": "abc"},
        proxy="http://127.0.0.1:8080",
    )
    assert client._session.headers["User-Agent"] == "TestUA/1.0"
    assert client._session.headers["X-Test"] == "1"
    assert client._session.cookies.get("sid") == "abc"
    assert client._session.proxies["https"] == "http://127.0.0.1:8080"


def test_trust_env_disabled():
    client = build_client()
    assert client._session.trust_env is False


# ---------------------------------------------------------------------
# Scope guard
# ---------------------------------------------------------------------


def test_scope_allows_host_and_subdomain(make_response, monkeypatch):
    client = build_client(scope="example.com")
    patch_send(monkeypatch, client, lambda m, u, d, h: make_response(url=u))
    client.get("https://example.com/a")
    client.get("https://api.example.com/b")


def test_scope_blocks_other_host():
    client = build_client(scope="example.com")
    with pytest.raises(OutOfScopeError):
        client.get("https://evil.com/x")


def test_scope_blocks_out_of_scope_redirect(make_response, monkeypatch):
    client = build_client(scope="example.com")

    def responder(m, u, d, h):
        return make_response(302, "", {"Location": "https://evil.com/y"}, url=u)

    patch_send(monkeypatch, client, responder)
    with pytest.raises(OutOfScopeError):
        client.get("https://example.com/redirect")


# ---------------------------------------------------------------------
# Redirect handling
# ---------------------------------------------------------------------


def test_post_302_switches_to_get(make_response, monkeypatch):
    client = build_client()

    def responder(m, u, d, h):
        if u == "https://t.local/login":
            return make_response(302, "", {"Location": "/home"}, url=u)
        return make_response(200, "home", url=u)

    calls = patch_send(monkeypatch, client, responder)
    resp = client.post("https://t.local/login", data={"u": "x"})
    assert resp.status_code == 200
    assert calls[0]["method"] == "POST" and calls[0]["data"] == {"u": "x"}
    assert calls[1]["method"] == "GET" and calls[1]["data"] is None
    assert calls[1]["url"] == "https://t.local/home"


def test_post_307_keeps_method_and_body(make_response, monkeypatch):
    client = build_client()

    def responder(m, u, d, h):
        if u == "https://t.local/step1":
            return make_response(307, "", {"Location": "/step2"}, url=u)
        return make_response(200, "done", url=u)

    calls = patch_send(monkeypatch, client, responder)
    client.post("https://t.local/step1", data={"a": "b"})
    assert calls[1]["method"] == "POST"
    assert calls[1]["data"] == {"a": "b"}


def test_no_redirect_following_when_disabled(make_response, monkeypatch):
    client = build_client()

    def responder(m, u, d, h):
        return make_response(302, "", {"Location": "/elsewhere"}, url=u)

    calls = patch_send(monkeypatch, client, responder)
    resp = client.get("https://t.local/a", allow_redirects=False)
    assert resp.status_code == 302
    assert len(calls) == 1


def test_too_many_redirects(make_response, monkeypatch):
    client = build_client(max_redirects=2)

    def responder(m, u, d, h):
        return make_response(302, "", {"Location": f"{u}x"}, url=u)

    patch_send(monkeypatch, client, responder)
    with pytest.raises(requests.exceptions.TooManyRedirects):
        client.get("https://t.local/a")


# ---------------------------------------------------------------------
# Retries
# ---------------------------------------------------------------------


def test_retry_on_connection_error_then_success(make_response, monkeypatch):
    client = build_client(max_retries=2, retry_backoff=0.0)
    attempts = {"n": 0}

    def flaky_send(method, url, *, data, params, headers, timeout, verify):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise requests.exceptions.ConnectionError("boom")
        return make_response(url=url)

    monkeypatch.setattr(client, "_send_raw", flaky_send)
    resp = client.get("https://t.local/x")
    assert resp.status_code == 200
    assert attempts["n"] == 3


def test_retry_exhausted_raises(monkeypatch):
    client = build_client(max_retries=1, retry_backoff=0.0)

    def always_fail(*args, **kwargs):
        raise requests.exceptions.ConnectionError("boom")

    monkeypatch.setattr(client, "_send_raw", always_fail)
    with pytest.raises(requests.exceptions.ConnectionError):
        client.get("https://t.local/x")


def test_no_retries_by_default(monkeypatch):
    client = build_client()
    attempts = {"n": 0}

    def flaky_send(method, url, *, data, params, headers, timeout, verify):
        attempts["n"] += 1
        raise requests.exceptions.ConnectionError("boom")

    monkeypatch.setattr(client, "_send_raw", flaky_send)
    with pytest.raises(requests.exceptions.ConnectionError):
        client.get("https://t.local/x")
    assert attempts["n"] == 1


# ---------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------


class FakeTime:
    """Deterministic time module replacement for the http_client."""

    def __init__(self):
        self.t = 1000.0
        self.sleeps: list[float] = []

    def monotonic(self):
        return self.t

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.t += seconds


def test_rate_limit_sleeps_between_requests(make_response, monkeypatch):
    fake_time = FakeTime()
    monkeypatch.setattr("redkit.core.http_client.time", fake_time)
    client = build_client(rate_limit=0.25)
    patch_send(monkeypatch, client, lambda m, u, d, h: make_response(url=u))

    client.get("https://t.local/a")
    client.get("https://t.local/a")
    client.get("https://t.local/a")

    # The first request never waits; subsequent ones respect the limit.
    assert len(fake_time.sleeps) == 2
    assert all(s == pytest.approx(0.25) for s in fake_time.sleeps)
