"""
modules/base_module.py — Abstract base class for all RedKit modules.

Every module must inherit from BaseModule and implement the run() method.
The interface enforces consistent option management, validation, and finding reporting.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)


class BaseModule(ABC):
    """Abstract base class that every RedKit module must subclass.

    Subclasses must define:
        - name (str): Human-readable display name.
        - description (str): One-line description shown in the module browser.
        - author (str): Author or attribution string.
        - options (dict): Configurable options dict (see option schema below).

    Option schema for each key in options::

        {
            "value": <current value or None>,
            "required": <bool>,
            "description": <str>,
        }
    """

    name: str = "Unnamed Module"
    description: str = "No description provided."
    author: str = "Unknown"
    category: str = "misc"
    options: dict[str, dict[str, Any]] = {}

    def __init__(self) -> None:
        """Initialise the module with an empty findings list and deep-copy options."""
        # Deep copy so subclass class-level dicts don't share state across instances
        import copy
        self.options = copy.deepcopy(self.__class__.options)
        self._findings: list[dict[str, Any]] = []
        logger.debug("Module '%s' initialised.", self.name)

    # ------------------------------------------------------------------
    # Option management
    # ------------------------------------------------------------------

    def set_option(self, key: str, value: Any) -> None:
        """Set the value of a module option.

        Args:
            key: The option name to update.
            value: The new value for that option.

        Raises:
            KeyError: If *key* does not exist in this module's options dict.
        """
        if key not in self.options:
            raise KeyError(f"Unknown option '{key}' for module '{self.name}'.")
        self.options[key]["value"] = value
        logger.debug("Module '%s': option '%s' set to '%s'.", self.name, key, value)

    def validate_options(self) -> None:
        """Validate that all required options have been set.

        Raises:
            ValueError: Listing every missing required option name.
        """
        missing = [
            key
            for key, meta in self.options.items()
            if meta.get("required") and (meta.get("value") is None or meta.get("value") == "")
        ]
        if missing:
            raise ValueError(
                f"Module '{self.name}' is missing required options: {', '.join(missing)}"
            )
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

    def _add_finding(
        self,
        finding_type: str,
        severity: str,
        title: str,
        detail: str,
        evidence: str = "",
    ) -> None:
        """Append a structured finding to the internal findings list.

        Args:
            finding_type: Category label, e.g. "XSS", "SQLi", "Subdomain".
            severity: One of CRITICAL, HIGH, MEDIUM, LOW, INFO.
            title: Short, descriptive title of the finding.
            detail: Full description / explanation.
            evidence: Raw proof (payload, response snippet, etc.).
        """
        finding: dict[str, Any] = {
            "type": finding_type,
            "severity": severity.upper(),
            "title": title,
            "detail": detail,
            "evidence": evidence,
        }
        self._findings.append(finding)
        logger.debug(
            "Module '%s': finding added — [%s] %s", self.name, severity, title
        )

    def get_findings(self) -> list[dict[str, Any]]:
        """Return all findings collected during the last run().

        Returns:
            List of finding dicts, each with keys: type, severity, title, detail, evidence.
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
        3. Append findings via self._add_finding().
        4. Handle all exceptions internally — never let a module crash the TUI.
        """
        ...

    def __repr__(self) -> str:
        return f"<Module name={self.name!r} category={self.category!r}>"
