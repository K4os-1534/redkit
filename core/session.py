"""
core/session.py — Session manager for a RedKit run.

Stores the current target, active module, scan history, and findings
accumulated from all modules run during this session.
"""

import logging
import re
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


class Session:
    """Manages the lifecycle of a single RedKit session.

    A session begins when the tool starts and ends when the user exits.
    It stores the target URL, selected module, and all findings generated
    by every module run during the session.
    """

    def __init__(self) -> None:
        """Initialise an empty session."""
        self.target: Optional[str] = None
        self.active_module: Optional[Any] = None  # BaseModule instance
        self.scan_history: list[dict[str, Any]] = []
        self._all_findings: list[dict[str, Any]] = []
        self.start_time: datetime = datetime.now(tz=timezone.utc)
        logger.debug("Session initialised at %s.", self.start_time.isoformat())

    # ------------------------------------------------------------------
    # Target management
    # ------------------------------------------------------------------

    def set_target(self, url: str) -> str:
        """Validate, normalise, and store the target URL.

        Ensures the URL has an http:// or https:// scheme. If missing,
        defaults to https://.

        Args:
            url: Raw URL string provided by the user.

        Returns:
            The normalised URL that was stored.

        Raises:
            ValueError: If the URL is empty or clearly invalid.
        """
        url = url.strip()
        if not url:
            raise ValueError("Target URL cannot be empty.")

        # Prepend scheme if missing
        if not re.match(r"^https?://", url, re.IGNORECASE):
            url = "https://" + url

        # Basic sanity check — must look like a hostname
        pattern = re.compile(
            r"^https?://"
            r"([a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+)"
            r"$"
        )
        if not pattern.match(url):
            raise ValueError(f"'{url}' does not appear to be a valid URL.")

        self.target = url
        logger.debug("Session target set to: %s", self.target)
        return self.target

    def get_target_domain(self) -> str:
        """Return a filesystem-safe version of the target domain.

        Strips the scheme and replaces non-alphanumeric chars with underscores.

        Returns:
            Sanitised domain string for use in filenames.
        """
        if not self.target:
            return "unknown"
        domain = re.sub(r"^https?://", "", self.target)
        domain = re.sub(r"[^\w\-.]", "_", domain)
        return domain.rstrip("_/")

    # ------------------------------------------------------------------
    # Module management
    # ------------------------------------------------------------------

    def set_active_module(self, module: Any) -> None:
        """Set the currently active module.

        Args:
            module: An instantiated BaseModule subclass.
        """
        self.active_module = module
        logger.debug("Active module set to: %s", module.name)

    # ------------------------------------------------------------------
    # Findings management
    # ------------------------------------------------------------------

    def add_findings(self, module_name: str, findings_list: list[dict[str, Any]]) -> None:
        """Append findings from a module run to the session log.

        Args:
            module_name: The name of the module that produced the findings.
            findings_list: List of finding dicts (type, severity, title, detail, evidence).
        """
        timestamp = datetime.now(tz=timezone.utc).isoformat()
        for finding in findings_list:
            enriched = {**finding, "module": module_name, "timestamp": timestamp}
            self._all_findings.append(enriched)

        self.scan_history.append(
            {
                "module": module_name,
                "timestamp": timestamp,
                "finding_count": len(findings_list),
            }
        )
        logger.debug(
            "Added %d findings from module '%s'.", len(findings_list), module_name
        )

    def get_all_findings(self) -> list[dict[str, Any]]:
        """Return the full, flat list of all findings from all module runs.

        Returns:
            List of enriched finding dicts (includes 'module' and 'timestamp' keys).
        """
        return list(self._all_findings)

    def get_findings_by_severity(self, severity: str) -> list[dict[str, Any]]:
        """Filter all findings by severity level.

        Args:
            severity: Severity string (e.g. 'CRITICAL', 'HIGH').

        Returns:
            Filtered list of matching findings.
        """
        return [f for f in self._all_findings if f.get("severity", "").upper() == severity.upper()]

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_session(self) -> dict[str, Any]:
        """Return a dictionary of all session data suitable for reporting.

        Returns:
            Dict containing target, start time, scan history, and all findings.
        """
        return {
            "target": self.target,
            "start_time": self.start_time.isoformat(),
            "scan_date": self.start_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "scan_history": self.scan_history,
            "findings": self._all_findings,
            "finding_count": len(self._all_findings),
            "severity_summary": self._severity_summary(),
        }

    def _severity_summary(self) -> dict[str, int]:
        """Count findings per severity level.

        Returns:
            Dict mapping severity label to count.
        """
        levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        return {
            lvl: sum(1 for f in self._all_findings if f.get("severity", "").upper() == lvl)
            for lvl in levels
        }
