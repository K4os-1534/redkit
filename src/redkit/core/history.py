"""
core/history.py — Lightweight persistence for recent targets and module options.

Stores a small JSON file (default: ``~/.redkit/history.json``) so the TUI can
offer recent targets and restore the last-used options per module. Only
non-secret convenience data is stored: target URLs and option values.
"""

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: Default history file location.
DEFAULT_HISTORY_PATH = Path.home() / ".redkit" / "history.json"

#: Maximum number of recent targets remembered.
MAX_TARGETS = 10


def _empty_history() -> dict[str, Any]:
    """Return the empty history structure."""
    return {"targets": [], "modules": {}}


def history_path(config: dict[str, Any] | None = None) -> Path:
    """Resolve the history file path from config (or the default).

    Args:
        config: Optional RedKit configuration dict with a ``history_file`` key.

    Returns:
        Path to the history file.
    """
    configured = str((config or {}).get("history_file") or "").strip()
    if configured:
        return Path(configured).expanduser()
    return DEFAULT_HISTORY_PATH


def load_history(path: Path) -> dict[str, Any]:
    """Load the history structure, tolerating missing or corrupt files.

    Args:
        path: History file path.

    Returns:
        Dict with ``targets`` (list of str) and ``modules`` (dict of dicts).
    """
    if not path.is_file():
        return _empty_history()
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Could not read history file %s (%s) — starting fresh.", path, exc)
        return _empty_history()
    if not isinstance(data, dict):
        logger.warning("History file %s has unexpected format — starting fresh.", path)
        return _empty_history()
    targets = data.get("targets", [])
    modules = data.get("modules", {})
    return {
        "targets": [str(t) for t in targets if isinstance(t, str)] if isinstance(targets, list) else [],
        "modules": {str(k): v for k, v in modules.items() if isinstance(v, dict)}
        if isinstance(modules, dict)
        else {},
    }


def save_history(path: Path, history: dict[str, Any]) -> None:
    """Persist the history structure (best-effort; failures are logged only).

    Args:
        path: Destination file path.
        history: History dict as produced by :func:`load_history`.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(history, fh, indent=2)
    except OSError as exc:
        logger.warning("Could not write history file %s: %s", path, exc)


def record_target(path: Path, target: str, enabled: bool = True) -> None:
    """Add a target to the recent-targets list (most recent first, deduped).

    Args:
        path: History file path.
        target: The normalised target URL.
        enabled: When False, this is a no-op (respects ``save_history: false``).
    """
    if not enabled or not target:
        return
    history = load_history(path)
    targets = [t for t in history["targets"] if t != target]
    targets.insert(0, target)
    history["targets"] = targets[:MAX_TARGETS]
    save_history(path, history)


def recent_targets(path: Path) -> list[str]:
    """Return the recorded recent targets, most recent first.

    Args:
        path: History file path.

    Returns:
        List of target URLs (may be empty).
    """
    return load_history(path)["targets"]


def record_module_options(
    path: Path, module_name: str, options: dict[str, Any], enabled: bool = True
) -> None:
    """Remember a module's current option values (excluding 'target').

    Args:
        path: History file path.
        module_name: The module's display name.
        options: The module's options dict (name → meta with "value").
        enabled: When False, this is a no-op (respects ``save_history: false``).
    """
    if not enabled or not module_name:
        return
    values = {
        key: meta.get("value")
        for key, meta in options.items()
        if key != "target" and meta.get("value") is not None
    }
    if not values:
        return
    history = load_history(path)
    history["modules"][module_name] = values
    save_history(path, history)


def load_module_options(path: Path, module_name: str) -> dict[str, Any]:
    """Return the last-used option values for a module (may be empty).

    Args:
        path: History file path.
        module_name: The module's display name.

    Returns:
        Dict mapping option name to last-used value.
    """
    return dict(load_history(path)["modules"].get(module_name, {}))
