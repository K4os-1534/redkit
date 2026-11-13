"""Tests for redkit.core.profiles — builtin + user profiles and resolution."""

import pytest

from redkit.core.engine import Engine
from redkit.core.profiles import BUILTIN_PROFILES, load_profiles, resolve_profile


def test_builtin_profiles_present():
    profiles = load_profiles(extra_path=None)
    for name in ("Quick Recon", "Full Recon", "Vulnerability Sweep"):
        assert name in profiles
    assert profiles["Vulnerability Sweep"] == ["XSS Tester", "SQLi Tester", "LFI Tester"]


def test_user_profiles_merge_and_shadow(tmp_path):
    p = tmp_path / "profiles.yaml"
    p.write_text("Night Shift:\n  - Technology Fingerprinter\nQuick Recon:\n  - Subdomain Enumerator\n")
    profiles = load_profiles(extra_path=p)
    assert profiles["Night Shift"] == ["Technology Fingerprinter"]
    assert profiles["Quick Recon"] == ["Subdomain Enumerator"]  # shadowed
    assert "Full Recon" in profiles  # builtins survive


def test_malformed_yaml_is_tolerated(tmp_path):
    p = tmp_path / "profiles.yaml"
    p.write_text("a: [unclosed\n")
    profiles = load_profiles(extra_path=p)
    assert set(profiles) == set(BUILTIN_PROFILES)


def test_malformed_entries_are_ignored(tmp_path):
    p = tmp_path / "profiles.yaml"
    p.write_text("Bad Type:\n  - 42\nEmpty:\n  []\nGood:\n  - XSS Tester\n")
    profiles = load_profiles(extra_path=p)
    assert "Bad Type" not in profiles
    assert "Empty" not in profiles
    assert profiles["Good"] == ["XSS Tester"]


@pytest.fixture
def engine():
    e = Engine(config={})
    e.discover()
    return e


def test_resolve_profile_returns_ordered_modules(engine):
    modules = resolve_profile(engine, "quick recon")  # case-insensitive
    assert [m.name for m in modules] == ["Technology Fingerprinter", "Directory Brute-Forcer"]


def test_resolve_unknown_profile_raises(engine):
    with pytest.raises(ValueError, match="Available"):
        resolve_profile(engine, "No Such Profile")


def test_resolve_profile_with_unknown_module_raises(engine):
    profiles = {"Broken": ["XSS Tester", "Not A Module"]}
    with pytest.raises(ValueError, match="unknown module"):
        resolve_profile(engine, "Broken", profiles=profiles)
