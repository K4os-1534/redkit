"""
core/report.py — Report generator for RedKit scan sessions.

Produces two output files per session:
    - A JSON file containing the full raw findings dump.
    - An HTML file rendered via Jinja2 from templates/report.html.j2.

Both files are written to the reports/ directory under the project root.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_TEMPLATES_DIR = _PROJECT_ROOT / "templates"
_REPORTS_DIR = _PROJECT_ROOT / "reports"


def _get_jinja_env():
    """Return a configured Jinja2 Environment loaded from the templates directory."""
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape

        env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=select_autoescape(["html"]),
        )
        return env
    except ImportError as exc:
        raise RuntimeError("jinja2 is required for HTML reports. Install with: pip install jinja2") from exc


class Reporter:
    """Generates JSON and HTML reports from session data.

    Usage::

        reporter = Reporter(session.export_session())
        json_path, html_path = reporter.generate()
    """

    def __init__(self, session_data: dict[str, Any]) -> None:
        """Initialise the reporter with exported session data.

        Args:
            session_data: Dict returned by Session.export_session().
        """
        self.session_data = session_data
        _REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    def _build_filename_base(self) -> str:
        """Build the base filename string (without extension).

        Format: redkit_{sanitised_domain}_{timestamp}

        Returns:
            Base filename string.
        """
        target = self.session_data.get("target") or "unknown"
        import re
        domain = re.sub(r"^https?://", "", target)
        domain = re.sub(r"[^\w\-.]", "_", domain).strip("_/")[:40]
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        return f"redkit_{domain}_{ts}"

    def generate(self) -> tuple[Path, Path]:
        """Write JSON and HTML reports to the reports/ directory.

        Returns:
            Tuple of (json_path, html_path) as Path objects.

        Raises:
            RuntimeError: If the HTML template cannot be rendered.
        """
        base = self._build_filename_base()
        json_path = _REPORTS_DIR / f"{base}.json"
        html_path = _REPORTS_DIR / f"{base}.html"

        self._write_json(json_path)
        self._write_html(html_path)

        return json_path, html_path

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

    def _write_html(self, path: Path) -> None:
        """Render the Jinja2 template and write the HTML report.

        Args:
            path: Destination file path.
        """
        try:
            env = _get_jinja_env()
            template = env.get_template("report.html.j2")

            # Group findings by severity for the template
            severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            grouped: dict[str, list[dict[str, Any]]] = {s: [] for s in severity_order}
            for finding in self.session_data.get("findings", []):
                sev = finding.get("severity", "INFO").upper()
                grouped.setdefault(sev, []).append(finding)

            html_content = template.render(
                session=self.session_data,
                grouped_findings=grouped,
                severity_order=severity_order,
                severity_summary=self.session_data.get("severity_summary", {}),
                report_generated=datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            )

            with open(path, "w", encoding="utf-8") as fh:
                fh.write(html_content)
            logger.info("HTML report written to: %s", path)

        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to write HTML report: %s", exc, exc_info=True)
            raise RuntimeError(f"HTML report generation failed: {exc}") from exc
