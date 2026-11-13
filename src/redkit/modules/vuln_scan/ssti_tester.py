"""
modules/vuln_scan/ssti_tester.py — Server-Side Template Injection (SSTI) tester.

Injects arithmetic template expressions across the major template syntaxes
(Jinja2, Twig, Java EL/Freemarker, ERB/EJS, Ruby #{}) and confirms only when
the unique numeric result (1337 × 1337 = 1787569) appears in the response.

The arithmetic marker makes false positives practically impossible: a value
that the application echoes verbatim never renders as the computed product,
and the benign baseline response is checked to not already contain it.
"""

import logging

from requests.utils import quote
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from redkit.modules.base_module import BaseModule

logger = logging.getLogger(__name__)

# (payload, expected_marker, engine_family)
SSTI_PAYLOADS: list[tuple[str, str, str]] = [
    ("{{1337*1337}}", "1787569", "Jinja2 / Twig"),
    ("${1337*1337}", "1787569", "Java EL / Freemarker"),
    ("<%= 1337*1337 %>", "1787569", "ERB / EJS"),
    ("#{1337*1337}", "1787569", "Ruby (HAML/Slim)"),
    ("{{7*'7'}}", "7777777", "Jinja2 ( Twig returns 49)"),
]


class SstiTester(BaseModule):
    """Test a query parameter for server-side template injection.

    Confirms SSTI only when a template arithmetic expression's unique
    computed value is reflected — verbatim reflection alone is never
    reported, keeping the false-positive rate effectively zero.
    """

    name = "SSTI Tester"
    description = "Tests a query parameter for server-side template injection via arithmetic markers."
    author = "K4os"
    category = "vuln_scan"

    options = {
        "target": {
            "value": None,
            "required": True,
            "description": "Target URL (e.g. https://example.com/page).",
        },
        "param": {
            "value": None,
            "required": True,
            "description": "Query parameter name to inject into (e.g. name, page).",
        },
        "timeout": {
            "value": 10,
            "required": False,
            "type": int,
            "description": "HTTP request timeout in seconds (default: 10).",
        },
    }

    def run(self) -> None:
        """Send SSTI payloads and confirm only on computed arithmetic markers."""
        self.clear_findings()
        self.validate_options()

        target = self.get_option("target")
        param = self.get_option("param")
        http = self.http_client(target)

        confirmed: set[str] = set()  # engine families already reported

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            task = progress.add_task(f"Testing SSTI payloads on {target}", total=len(SSTI_PAYLOADS))
            self._progress = progress

            # Baseline: benign value must not contain the marker result.
            try:
                baseline_body = http.get(f"{target}?{param}=redkit-baseline-probe").text
            except Exception as exc:  # noqa: BLE001
                logger.warning("Baseline request failed — aborting SSTI test: %s", exc)
                return

            for payload, marker, family in SSTI_PAYLOADS:
                progress.advance(task)
                if family in confirmed:
                    continue
                url = f"{target}?{param}={quote(payload)}"
                try:
                    resp = http.get(url)
                    if marker in resp.text and marker not in baseline_body:
                        confirmed.add(family)
                        logger.warning("SSTI confirmed (%s): %s", family, payload)
                        self.add_finding(
                            finding_type="SSTI",
                            severity="CRITICAL",
                            title=f"Server-side template injection detected ({family})",
                            detail=(
                                f"The parameter '{param}' is evaluated by a {family} template engine: "
                                f"the injected expression '{payload}' was computed server-side and its "
                                f"result ({marker}) appears in the response. Template injection of this "
                                f"family commonly escalates to remote code execution."
                            ),
                            evidence=(
                                f"GET {url}\nPayload: {payload}\n"
                                f"Computed marker found in response: {marker}\n"
                                f"(Marker absent from benign baseline response.)"
                            ),
                            # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
                            cvss=9.8,
                        )
                except Exception as exc:  # noqa: BLE001 — keep scanning remaining payloads
                    logger.debug("Request error for SSTI payload '%s': %s", payload, exc)

        total = len(self.get_findings())
        logger.info("SSTI testing complete: %d finding(s).", total)
