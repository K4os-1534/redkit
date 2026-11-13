"""Tests for redkit.modules.base_module — options, coercion, findings."""

import pytest

from redkit.modules.base_module import BaseModule


class Dummy(BaseModule):
    name = "Dummy"
    description = "test module"
    author = "tester"
    category = "misc"
    options = {
        "target": {"value": None, "required": True, "description": "target"},
        "threads": {"value": 5, "required": False, "type": int, "description": "threads"},
        "rate": {"value": 0.5, "required": False, "type": float, "description": "rate"},
        "flag": {"value": False, "required": False, "type": bool, "description": "flag"},
        "label": {"value": "x", "required": False, "type": str, "description": "label"},
    }

    def run(self) -> None:
        pass


def test_options_deep_copied_per_instance():
    a, b = Dummy(), Dummy()
    a.set_option("threads", 9)
    assert b.get_option("threads") == 5


def test_set_option_coerces_types_from_strings():
    m = Dummy()
    m.set_option("threads", "12")
    m.set_option("rate", "1.5")
    m.set_option("flag", "true")
    assert m.get_option("threads") == 12
    assert m.get_option("rate") == 1.5
    assert m.get_option("flag") is True


def test_set_option_accepts_native_types():
    m = Dummy()
    m.set_option("threads", 7)
    m.set_option("flag", True)
    assert m.get_option("threads") == 7
    assert m.get_option("flag") is True


def test_set_option_invalid_int_raises_valueerror():
    m = Dummy()
    with pytest.raises(ValueError):
        m.set_option("threads", "abc")


def test_set_option_invalid_bool_raises_valueerror():
    m = Dummy()
    with pytest.raises(ValueError):
        m.set_option("flag", "maybe")


def test_set_option_unknown_key_raises_keyerror():
    m = Dummy()
    with pytest.raises(KeyError):
        m.set_option("nope", 1)


def test_validate_options_missing_required():
    m = Dummy()
    with pytest.raises(ValueError, match="target"):
        m.validate_options()


def test_validate_options_passes_when_complete():
    m = Dummy()
    m.set_option("target", "https://example.com")
    m.validate_options()  # should not raise


def test_add_finding_and_legacy_alias():
    m = Dummy()
    m.add_finding("T", "high", "title", "detail", "ev")
    m._add_finding("T", "CRITICAL", "title2", "detail2")
    findings = m.get_findings()
    assert len(findings) == 2
    assert findings[0].severity.value == "HIGH"
    assert findings[1].severity.value == "CRITICAL"


def test_clear_findings():
    m = Dummy()
    m.add_finding("T", "INFO", "t", "d")
    m.clear_findings()
    assert m.get_findings() == []


def test_http_client_builds_from_config():
    m = Dummy()
    m.config = {
        "default_user_agent": "TestUA/9",
        "default_timeout": 3,
        "verify_ssl": False,
        "proxy": "http://127.0.0.1:8080",
    }
    client = m.http_client("https://example.com/x")
    assert client._session.headers["User-Agent"] == "TestUA/9"
    assert client.config.timeout == 3.0
    assert client.config.verify_ssl is False
    assert client.config.proxy == "http://127.0.0.1:8080"
    assert client.scope == "example.com"


def test_add_finding_accepts_cvss():
    m = Dummy()
    m.add_finding("T", "CRITICAL", "title", "detail", cvss=9.8)
    assert m.get_findings()[0].cvss == 9.8


def test_live_feed_prints_through_progress_console():
    from rich.console import Console

    m = Dummy()
    m.config = {"live_feed": True}
    feed = Console(record=True, width=200)
    m._progress = type("P", (), {"console": feed})()
    m.add_finding("T", "CRITICAL", "bad thing happened", "detail")
    text = feed.export_text()
    assert "CRITICAL" in text and "bad thing happened" in text


def test_live_feed_disabled_by_config():
    from rich.console import Console

    m = Dummy()
    m.config = {"live_feed": False}
    feed = Console(record=True, width=200)
    m._progress = type("P", (), {"console": feed})()
    m.add_finding("T", "CRITICAL", "should not appear", "detail")
    assert "should not appear" not in feed.export_text()
