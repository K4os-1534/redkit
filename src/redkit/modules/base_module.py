"""
modules/base_module.py — Abstract base class for all RedKit modules.

Every module must inherit from BaseModule and implement the run() method.
The interface enforces consistent option management, validation, config
access, HTTP usage, and finding reporting.
"""

import copy
import logging
from abc import ABC, abstractmethod
from typing import Any
from urllib.parse import urlparse

from rich.console import Console

from redkit import __version__
from redkit.core.http_client import HttpClient, HttpClientConfig
from redkit.core.models import SEVERITY_STYLES, Finding, Severity

logger = logging.getLogger(__name__)

#: Option types accepted in the "type" key of an option definition.
_VALID_OPTION_TYPES = (int, float, str, bool)

#: Console used for the live finding feed when no Progress bar is active.
_feed_console = Console()


class BaseModule(ABC):
    """Abstract base class that every RedKit module must subclass.

    Subclasses must define:
        - name (str): Human-readable display name.
        - description (str): One-line description shown in the module browser.
        - author (str): Author or attribution string.
        - category (str): Must match the subdirectory the module lives in.
        - options (dict): Configurable options dict (see option schema below).

    Option schema for each key in options::

        {
            "value": <current value or None>,
            "required": <bool>,
            "type": <int | float | str | bool>,   # optional, enables coercion
            "description": <str>,
        }

    The global configuration dict is injected via the constructor; access it
    with :meth:`get_config`. Network activity should go through a client
    from :meth:`http_client` so scope checks, TLS settings, proxying, and
    rate limits apply uniformly.
    """

    name: str = "Unnamed Module"
    description: str = "No description provided."
    author: str = "Unknown"
    category: str = "misc"
    options: dict[str, dict[str, Any]] = {}

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """Initialise the module with an empty findings list and copied options.

        Args:
            config: Global RedKit configuration dict (injected by the Engine).
                When omitted, an empty config is used and code should fall
                back to sensible defaults.
        """
        # Deep copy so subclass class-level dicts don't share state across instances
        self.config: dict[str, Any] = config if isinstance(config, dict) else {}
        self.options = copy.deepcopy(self.__class__.options)
        self._findings: list[Finding] = []
        #: Active rich Progress instance, set by modules inside run(). The
        #: live finding feed prints through it so progress bars stay intact.
        self._progress: Any = None
        logger.debug("Module '%s' initialised.", self.name)

    # ------------------------------------------------------------------
    # Configuration access
    # ------------------------------------------------------------------

    def get_config(self, key: str, default: Any = None) -> Any:
        """Return a value from the injected configuration.

        Args:
            key: Configuration key.
            default: Value returned when the key is absent.

        Returns:
            Configuration value or *default*.
        """
        return self.config.get(key, default)

    def http_client(self, target: str | None = None, enforce_scope: bool = True) -> HttpClient:
        """Build an HttpClient from the injected configuration.

        Args:
            target: Optional target URL; its host becomes the request scope
                (requests and redirect hops to other hosts are refused).
            enforce_scope: When False the client sends requests anywhere.
                Only for modules that must consult third-party services
                about the target (e.g. archive APIs) — never for probing
                the target itself.

        Returns:
            Configured HttpClient instance.
        """
        cfg = HttpClientConfig(
            user_agent=str(
                self.get_config(
                    "default_user_agent",
                    f"RedKit/{__version__} (Authorized Security Testing)",
                )
            ),
            timeout=float(self.get_config("default_timeout", 10)),
            verify_ssl=bool(self.get_config("verify_ssl", True)),
            proxy=str(self.get_config("proxy") or "") or None,
            rate_limit=float(self.get_config("rate_limit", 0.0)),
            max_retries=int(self.get_config("max_retries", 0)),
            max_redirects=int(self.get_config("max_redirects", 10)),
            extra_headers=dict(self.get_config("custom_headers") or {}),
            cookies=dict(self.get_config("custom_cookies") or {}),
        )
        scope = urlparse(target).hostname if target and enforce_scope else None
        return HttpClient(cfg, scope=scope)

    # ------------------------------------------------------------------
    # Option management
    # ------------------------------------------------------------------

    def set_option(self, key: str, value: Any) -> None:
        """Set the value of a module option, coercing to the declared type.

        Args:
            key: The option name to update.
            value: The new value for that option.

        Raises:
            KeyError: If *key* does not exist in this module's options dict.
            ValueError: If the value cannot be coerced to the option's type.
        """
        if key not in self.options:
            raise KeyError(f"Unknown option '{key}' for module '{self.name}'.")
        meta = self.options[key]
        declared = meta.get("type")
        if declared is not None and value is not None:
            value = self._coerce_option(key, value, declared)
        meta["value"] = value
        logger.debug("Module '%s': option '%s' set to %r.", self.name, key, value)

    @staticmethod
    def _coerce_option(key: str, value: Any, declared: Any) -> Any:
        """Coerce *value* to the declared option type.

        Args:
            key: Option name (for error messages).
            value: Raw value (typically a string from the TUI/CLI).
            declared: Expected type (int, float, str, or bool).

        Returns:
            The coerced value.

        Raises:
            ValueError: If coercion fails or the type is unsupported.
        """
        if declared not in _VALID_OPTION_TYPES:
            raise ValueError(
                f"Option '{key}' declares unsupported type {declared!r} "
                f"(expected one of: {', '.join(t.__name__ for t in _VALID_OPTION_TYPES)})"
            )
        if declared is bool:
            if isinstance(value, bool):
                return value
            text = str(value).strip().lower()
            if text in ("true", "yes", "1", "on"):
                return True
            if text in ("false", "no", "0", "off"):
                return False
            raise ValueError(f"Option '{key}' expects a boolean, got '{value}'.")
        if declared is int:
            if isinstance(value, bool):  # bool is a subclass of int — reject
                raise ValueError(f"Option '{key}' expects an integer, got '{value}'.")
            try:
                return int(str(value).strip())
            except ValueError:
                raise ValueError(f"Option '{key}' expects an integer, got '{value}'.") from None
        if declared is float:
            try:
                return float(str(value).strip())
            except ValueError:
                raise ValueError(f"Option '{key}' expects a number, got '{value}'.") from None
        return str(value)

    def validate_options(self) -> None:
        """Validate that required options are set and values match their types.

        Raises:
            ValueError: Listing every missing required option or invalid value.
        """
        problems: list[str] = []
        for key, meta in self.options.items():
            value = meta.get("value")
            if meta.get("required") and (value is None or value == ""):
                problems.append(f"missing required option '{key}'")
                continue
            declared = meta.get("type")
            if value is not None and declared is not None and not isinstance(value, declared):
                # Values are coerced in set_option(); a mismatch means the
                # option dict was mutated directly — correct it if possible.
                try:
                    meta["value"] = self._coerce_option(key, value, declared)
                except ValueError:
                    problems.append(f"option '{key}' expects {declared.__name__}, got {value!r}")
        if problems:
            raise ValueError(f"Module '{self.name}': " + "; ".join(problems))
        logger.debug("Module '%s': all required options validated.", self.name)

    def get_option(self, key: str) -> Any:
        """Return the current value of a named option.

        Args:
            key: Option name.

        Returns:
            The option's current value.
        """
        return self.options[key]["value"]

    # ------------------------------------------------------------------
    # Findings management
    # ------------------------------------------------------------------

    def add_finding(
        self,
        finding_type: str,
        severity: str,
        title: str,
        detail: str,
        evidence: str = "",
        cvss: float | None = None,
    ) -> None:
        """Append a structured finding to the module's findings list.

        Findings are also echoed to the live finding feed (see
        :meth:`_feed_finding`) unless disabled via the ``live_feed`` config
        key.

        Args:
            finding_type: Category label, e.g. "XSS", "SQLi", "Subdomain".
            severity: One of CRITICAL, HIGH, MEDIUM, LOW, INFO.
            title: Short, descriptive title of the finding.
            detail: Full description / explanation.
            evidence: Raw proof (payload, response snippet, etc.).
            cvss: Optional CVSS v3.1 base score (0.0–10.0) for confirmed
                vulnerabilities; omit for informational findings.
        """
        finding = Finding(
            type=finding_type,
            severity=Severity.parse(severity),
            title=title,
            detail=detail,
            evidence=evidence,
            cvss=cvss,
        )
        self._findings.append(finding)
        self._feed_finding(finding)
        logger.debug("Module '%s': finding added — [%s] %s", self.name, severity, title)

    def _feed_finding(self, finding: Finding) -> None:
        """Echo a finding to the live feed, one colour-coded line.

        Prints through the active Progress console (set by the module as
        ``self._progress``) so in-place progress bars are redrawn cleanly;
        falls back to a plain console. Disabled when the ``live_feed``
        config key is false.

        Args:
            finding: The finding just recorded.
        """
        if not bool(self.get_config("live_feed", True)):
            return
        style = SEVERITY_STYLES.get(finding.severity.value, "white")
        progress = self._progress
        target_console = progress.console if progress is not None else _feed_console
        try:
            target_console.print(f"  [{style}][{finding.severity.value}][/{style}] {finding.title}")
        except Exception:  # noqa: BLE001 — the feed must never break a scan
            logger.debug("Live feed print failed for finding '%s'.", finding.title)

    #: Backwards-compatible alias for add_finding().
    _add_finding = add_finding

    def get_findings(self) -> list[Finding]:
        """Return all findings collected during the last run().

        Returns:
            List of Finding objects.
        """
        return list(self._findings)

    def clear_findings(self) -> None:
        """Clear the findings list. Called automatically at the start of run()."""
        self._findings.clear()
        logger.debug("Module '%s': findings cleared.", self.name)

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    @abstractmethod
    def run(self) -> None:
        """Execute the module's scanning/testing logic.

        Implementations must:
        1. Call self.clear_findings() at the start.
        2. Call self.validate_options() before any network activity.
        3. Obtain an HTTP client via self.http_client(target).
        4. Append findings via self.add_finding().
        5. Handle all exceptions internally — never let a module crash the TUI.
        """
        ...

    def __repr__(self) -> str:
        return f"<Module name={self.name!r} category={self.category!r}>"
