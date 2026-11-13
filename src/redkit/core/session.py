"""
core/session.py — Session manager for a RedKit run.

Stores the current target, active module, scan history, and findings
accumulated from all modules run during this session. Sessions can be
serialised to disk (save) and restored later (load) to resume work.
"""

import json
import logging
import re
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from redkit import __version__
from redkit.core.models import Finding

logger = logging.getLogger(__name__)


class Session:
    """Manages the lifecycle of a single RedKit session.

    A session begins when the tool starts and ends when the user exits.
    It stores the target URL, selected module, and all findings generated
    by every module run during the session.
    """

    def __init__(self) -> None:
        """Initialise an empty session."""
        self.target: str | None = None
        self.active_module: Any | None = None  # BaseModule instance
        self.scan_history: list[dict[str, Any]] = []
        self._all_findings: list[Finding] = []
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

    def add_findings(
        self,
        module_name: str,
        findings_list: Iterable[Finding | dict[str, Any]],
    ) -> None:
        """Append findings from a module run to the session log.

        Accepts Finding objects (current) or plain finding dicts (legacy)
        and normalises everything to Finding objects enriched with the
        module name and a timestamp.

        Args:
            module_name: The name of the module that produced the findings.
            findings_list: Findings as Finding objects or dicts.
        """
        timestamp = datetime.now(tz=timezone.utc).isoformat()
        count = 0
        for item in findings_list:
            finding = item if isinstance(item, Finding) else Finding.from_dict(item)
            finding.module = module_name
            finding.timestamp = timestamp
            self._all_findings.append(finding)
            count += 1

        self.scan_history.append(
            {
                "module": module_name,
                "timestamp": timestamp,
                "finding_count": count,
            }
        )
        logger.debug("Added %d findings from module '%s'.", count, module_name)

    def get_all_findings(self) -> list[Finding]:
        """Return the full, flat list of all findings from all module runs.

        Returns:
            List of Finding objects (module and timestamp populated).
        """
        return list(self._all_findings)

    def get_findings_by_severity(self, severity: str) -> list[Finding]:
        """Filter all findings by severity level.

        Args:
            severity: Severity string (e.g. 'CRITICAL', 'HIGH').

        Returns:
            Filtered list of matching findings.
        """
        target = severity.upper()
        return [f for f in self._all_findings if f.severity.value == target]

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
            "target_domain": self.get_target_domain(),
            "start_time": self.start_time.isoformat(),
            "scan_date": self.start_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "scan_history": self.scan_history,
            "findings": [f.to_dict() for f in self._all_findings],
            "finding_count": len(self._all_findings),
            "severity_summary": self._severity_summary(),
        }

    def _severity_summary(self) -> dict[str, int]:
        """Count findings per severity level.

        Returns:
            Dict mapping severity label to count.
        """
        levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        return {lvl: sum(1 for f in self._all_findings if f.severity.value == lvl) for lvl in levels}

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str | Path) -> Path:
        """Serialise the session to a JSON file so it can be resumed later.

        Args:
            path: Destination file path.

        Returns:
            The path that was written.

        Raises:
            OSError: The file could not be written.
        """
        out = Path(path)
        payload = {
            "redkit_version": __version__,
            "saved_at": datetime.now(tz=timezone.utc).isoformat(),
            "target": self.target,
            "start_time": self.start_time.isoformat(),
            "scan_history": self.scan_history,
            "findings": [f.to_dict() for f in self._all_findings],
        }
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        logger.info("Session saved to %s.", out)
        return out

    @classmethod
    def load(cls, path: str | Path) -> "Session":
        """Restore a session previously written by :meth:`save`.

        Args:
            path: Session JSON file path.

        Returns:
            Restored Session instance.

        Raises:
            ValueError: The file is missing, unreadable, or malformed.
        """
        src = Path(path)
        if not src.is_file():
            raise ValueError(f"Session file not found: {src}")
        try:
            with open(src, encoding="utf-8") as fh:
                payload = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Could not read session file {src}: {exc}") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("findings", []), list):
            raise ValueError(f"{src} is not a RedKit session file.")

        session = cls()
        session.target = payload.get("target")
        try:
            session.start_time = datetime.fromisoformat(str(payload["start_time"]))
        except (KeyError, ValueError):
            logger.warning("Session file has invalid start_time — keeping fresh timestamp.")
        history = payload.get("scan_history", [])
        session.scan_history = history if isinstance(history, list) else []
        session._all_findings = [
            Finding.from_dict(d) for d in payload.get("findings", []) if isinstance(d, dict)
        ]
        logger.info(
            "Session restored from %s (%d findings, target=%s).",
            src,
            len(session._all_findings),
            session.target,
        )
        return session
