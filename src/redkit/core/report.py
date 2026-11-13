"""
core/report.py — Report generator for RedKit scan sessions.

Produces three output files per session:
    - A JSON file containing the full raw findings dump.
    - An HTML file rendered via Jinja2 from templates/report.html.j2.
    - A Markdown file rendered from templates/report.md.j2 (for pasting
      into pentest documents).

All finding content is enriched with remediation guidance before
rendering. Files are written to the configured output directory
(default: ./reports).
"""

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from redkit import __version__
from redkit.core.models import remediation_for
from redkit.core.resources import templates_dir

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = templates_dir()


def _get_jinja_env(autoescape: bool) -> Any:
    """Return a configured Jinja2 Environment loaded from the templates directory.

    The HTML report must always autoescape: findings carry attacker-controlled
    content (reflected payloads, response snippets) that must never reach it
    unescaped. (select_autoescape would look at the file's *last* extension —
    .j2 — and silently disable escaping.) The Markdown report renders evidence
    inside code fences, where HTML entities would be wrong, so it is written
    as plain text with escaping disabled.

    Args:
        autoescape: Whether template output is HTML-escaped.

    Returns:
        Configured Jinja2 Environment.
    """
    try:
        from jinja2 import Environment, FileSystemLoader

        return Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=autoescape,
        )
    except ImportError as exc:
        raise RuntimeError("jinja2 is required for HTML reports. Install with: pip install jinja2") from exc


class Reporter:
    """Generates JSON, HTML, and Markdown reports from session data.

    Usage::

        reporter = Reporter(session.export_session(), output_dir="reports")
        json_path, html_path, md_path = reporter.generate()
    """

    def __init__(self, session_data: dict[str, Any], output_dir: str | Path = "reports") -> None:
        """Initialise the reporter with exported session data.

        Args:
            session_data: Dict returned by Session.export_session().
            output_dir: Directory the report files are written to.
        """
        self.session_data = session_data
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def _build_filename_base(self) -> str:
        """Build the base filename string (without extension).

        Format: redkit_{sanitised_domain}_{timestamp}

        Reuses the target domain already sanitised by Session.export_session()
        when present, falling back to sanitising the raw target.

        Returns:
            Base filename string.
        """
        domain = str(self.session_data.get("target_domain") or "")
        if not domain or domain == "unknown":
            target = str(self.session_data.get("target") or "unknown")
            domain = re.sub(r"^https?://", "", target)
            domain = re.sub(r"[^\w\-.]", "_", domain).strip("_/")
        domain = domain[:40]
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        return f"redkit_{domain}_{ts}"

    def _grouped_findings(self) -> tuple[list[str], dict[str, list[dict[str, Any]]]]:
        """Group findings by severity for the templates.

        Returns:
            Tuple of (severity_order, grouped_findings).
        """
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        grouped: dict[str, list[dict[str, Any]]] = {s: [] for s in severity_order}
        for finding in self.session_data.get("findings", []):
            sev = str(finding.get("severity", "INFO")).upper()
            grouped.setdefault(sev, []).append(finding)
        return severity_order, grouped

    def generate(self) -> tuple[Path, Path, Path]:
        """Write JSON, HTML, and Markdown reports to the output directory.

        Returns:
            Tuple of (json_path, html_path, md_path) as Path objects.

        Raises:
            RuntimeError: If a template cannot be rendered.
        """
        base = self._build_filename_base()
        json_path = self._output_dir / f"{base}.json"
        html_path = self._output_dir / f"{base}.html"
        md_path = self._output_dir / f"{base}.md"

        self._write_json(json_path)

        # Enrich finding dicts with remediation guidance for the reports.
        for finding in self.session_data.get("findings", []):
            finding["remediation"] = remediation_for(str(finding.get("type", "")))

        self._write_html(html_path)
        self._write_markdown(md_path)

        return json_path, html_path, md_path

    def _write_json(self, path: Path) -> None:
        """Serialise session data to a pretty-printed JSON file.

        Args:
            path: Destination file path.
        """
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(self.session_data, fh, indent=2, default=str)
            logger.info("JSON report written to: %s", path)
        except OSError as exc:
            logger.error("Failed to write JSON report: %s", exc)
            raise

    def _render_context(self) -> dict[str, Any]:
        """Build the shared Jinja2 render context for HTML/Markdown reports.

        Returns:
            Context dict with session, grouping, summary, and timestamps.
        """
        severity_order, grouped_findings = self._grouped_findings()
        return {
            "session": self.session_data,
            "grouped_findings": grouped_findings,
            "severity_order": severity_order,
            "severity_summary": self.session_data.get("severity_summary", {}),
            "report_generated": datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "redkit_version": __version__,
        }

    def _write_html(self, path: Path) -> None:
        """Render the Jinja2 HTML template and write the report.

        Args:
            path: Destination file path.
        """
        try:
            env = _get_jinja_env(autoescape=True)
            template = env.get_template("report.html.j2")
            html_content = template.render(**self._render_context())

            with open(path, "w", encoding="utf-8") as fh:
                fh.write(html_content)
            logger.info("HTML report written to: %s", path)

        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to write HTML report: %s", exc, exc_info=True)
            raise RuntimeError(f"HTML report generation failed: {exc}") from exc

    def _write_markdown(self, path: Path) -> None:
        """Render the Jinja2 Markdown template and write the report.

        Args:
            path: Destination file path.
        """
        try:
            env = _get_jinja_env(autoescape=False)
            template = env.get_template("report.md.j2")
            md_content = template.render(**self._render_context())

            with open(path, "w", encoding="utf-8") as fh:
                fh.write(md_content)
            logger.info("Markdown report written to: %s", path)

        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to write Markdown report: %s", exc, exc_info=True)
            raise RuntimeError(f"Markdown report generation failed: {exc}") from exc
