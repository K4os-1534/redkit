"""
core/config.py — Configuration loading for RedKit.

Loads ``config.yaml`` (from the current working directory unless an explicit
path is given) and merges it over the built-in defaults. Every key a user
can override appears in :data:`DEFAULTS`.
"""

import logging
from pathlib import Path
from typing import Any

import yaml

from redkit import __version__

logger = logging.getLogger(__name__)

#: Built-in defaults — every key a user can override in config.yaml.
DEFAULTS: dict[str, Any] = {
    "default_threads": 10,
    "default_timeout": 5,
    "default_user_agent": f"RedKit/{__version__} (Authorized Security Testing)",
    "output_dir": "reports",
    "max_findings_display": 50,
    "log_file": "redkit.log",
    "log_level": "DEBUG",
    "verify_ssl": True,
    "proxy": "",
    "rate_limit": 0.0,
    "max_retries": 0,
    "max_redirects": 10,
    "custom_headers": {},
    "custom_cookies": {},
    # --- TUI behaviour ---
    "ui_pause": True,  # "Press Enter to continue" after each action
    "ui_clear_screen": False,  # clear the screen + re-render banner (kills scrollback)
    "live_feed": True,  # echo findings to the console as they are discovered
    "ask_authorization": True,  # confirm written permission before the first scan
    # --- History (recent targets + last-used module options) ---
    "save_history": True,  # set false to disable ~/.redkit/history.json
    "history_file": "",  # override the default ~/.redkit/history.json
}


def user_config_path(explicit: Path | None = None) -> Path | None:
    """Return the config.yaml path to load, or None when there is none.

    Args:
        explicit: Explicit path passed via ``--config``; takes priority.

    Returns:
        Path to an existing config file, or None if not found.
    """
    if explicit is not None:
        return explicit if explicit.is_file() else None
    candidate = Path.cwd() / "config.yaml"
    return candidate if candidate.is_file() else None


def load_config(explicit: Path | None = None) -> dict[str, Any]:
    """Load configuration, merging config.yaml over the built-in defaults.

    Args:
        explicit: Explicit config file path (e.g. from ``--config``).

    Returns:
        Fully-merged configuration dict.
    """
    config = {**DEFAULTS, "custom_headers": {}, "custom_cookies": {}}
    path = user_config_path(explicit)
    if path is None:
        logger.debug("No config.yaml found — using built-in defaults.")
        return config
    try:
        with open(path, encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
        if not isinstance(loaded, dict):
            logger.warning("%s does not contain a YAML mapping — ignoring it.", path)
            return config
        config.update(loaded)
        logger.debug("Loaded configuration from %s.", path)
    except yaml.YAMLError as exc:
        logger.warning("Could not parse %s: %s — using defaults.", path, exc)
    except OSError as exc:
        logger.warning("Could not read %s: %s — using defaults.", path, exc)
    return config
