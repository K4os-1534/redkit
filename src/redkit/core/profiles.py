"""
core/profiles.py — Scan profiles: named groups of modules run in sequence.

Built-in profiles cover common workflows (recon sweeps, vulnerability
checks). Users can define additional profiles in a ``profiles.yaml`` file
in the working directory::

    My Profile:
      - Technology Fingerprinter
      - XSS Tester

Module names must match the modules' display names. Unknown names cause
the profile to be rejected with an error listing the offenders.
"""

import logging
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from redkit.core.engine import Engine
    from redkit.modules.base_module import BaseModule

logger = logging.getLogger(__name__)

#: Built-in profiles: display name → ordered module names.
BUILTIN_PROFILES: dict[str, list[str]] = {
    "Quick Recon": [
        "Technology Fingerprinter",
        "Directory Brute-Forcer",
    ],
    "Full Recon": [
        "Subdomain Enumerator",
        "Technology Fingerprinter",
        "Directory Brute-Forcer",
    ],
    "Vulnerability Sweep": [
        "XSS Tester",
        "SQLi Tester",
        "LFI Tester",
    ],
}


def load_profiles(extra_path: Path | None = None) -> dict[str, list[str]]:
    """Load built-in profiles plus any user-defined ``profiles.yaml``.

    The optional *extra_path* (default: ``./profiles.yaml`` in the current
    working directory) merges over the built-ins; a user profile may shadow
    a built-in name.

    Args:
        extra_path: Optional path to a user profiles file.

    Returns:
        Dict mapping profile name to ordered module names.
    """
    profiles: dict[str, list[str]] = {name: list(mods) for name, mods in BUILTIN_PROFILES.items()}

    path = extra_path if extra_path is not None else Path.cwd() / "profiles.yaml"
    if not path.is_file():
        return profiles

    try:
        with open(path, encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError) as exc:
        logger.warning("Could not load %s: %s — user profiles ignored.", path, exc)
        return profiles

    if not isinstance(loaded, dict):
        logger.warning("%s does not contain a mapping — user profiles ignored.", path)
        return profiles

    for name, modules in loaded.items():
        if not isinstance(name, str) or not isinstance(modules, list):
            logger.warning("Ignoring malformed profile entry %r in %s.", name, path)
            continue
        if not modules or not all(isinstance(m, str) and m.strip() for m in modules):
            logger.warning("Ignoring profile '%s' — it must list module names.", name)
            continue
        profiles[str(name)] = [m.strip() for m in modules]
        logger.debug("Loaded user profile '%s' from %s.", name, path)

    return profiles


def resolve_profile(
    engine: "Engine", name: str, profiles: dict[str, list[str]] | None = None
) -> list["BaseModule"]:
    """Resolve a profile name to its ordered list of module instances.

    Args:
        engine: Discovered Engine instance.
        name: Profile display name (case-insensitive).
        profiles: Profiles to search (defaults to :func:`load_profiles`).

    Returns:
        Ordered list of module instances.

    Raises:
        ValueError: The profile is unknown or references unknown modules;
            the message lists the profile names / unknown module names.
    """
    profile_map = profiles if profiles is not None else load_profiles()
    match = next((key for key in profile_map if key.lower() == name.lower()), None)
    if match is None:
        raise ValueError(f"Unknown profile '{name}'. Available: {', '.join(sorted(profile_map))}")

    modules: list[BaseModule] = []
    unknown: list[str] = []
    for module_name in profile_map[match]:
        module = engine.get_module_by_name(module_name)
        if module is None:
            unknown.append(module_name)
        else:
            modules.append(module)
    if unknown:
        raise ValueError(f"Profile '{match}' references unknown module(s): {', '.join(unknown)}")
    return modules
