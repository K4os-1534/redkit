"""
modules/vuln_scan/crlf_tester.py — CRLF (header) injection tester.

Injects CR/LF sequences followed by a canary header into a query parameter
and confirms only when the canary header actually appears in the *response
headers* — a condition only reachable if the server split or appended our
input into the header block. Single-encoded, double-encoded, and Unicode
newline variants are covered.

Verbatim reflection in the body alone is never reported, keeping the
false-positive rate at effectively zero.
"""

import logging
from urllib.parse import quote

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

_CANARY_NAME = "X-RedKit-Probe"
_CANARY_VALUE = "crlf-confirmed"

# (payload, note) — raw CR/LF sequences; quoting happens per-variant below.
CRLF_PAYLOADS: list[tuple[str, str]] = [
    (f"\r\n{_CANARY_NAME}: {_CANARY_VALUE}", "single-encoded CRLF"),
    (f"%0d%0a{_CANARY_NAME}: {_CANARY_VALUE}", "pre-encoded CRLF"),
    (f"%250d%250a{_CANARY_NAME}: {_CANARY_VALUE}", "double-encoded CRLF"),
    (f"％０ｄ％０ａ{_CANARY_NAME}: {_CANARY_VALUE}", "unicode newline bypass"),
]


class CrlfTester(BaseModule):
    """Test a query parameter for CRLF injection into response headers."""

    name = "CRLF Injection Tester"
    description = "Tests a query parameter for CRLF injection via response-header canaries."
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
            "description": "Query parameter name to inject into (e.g. path, redirect, page).",
        },
        "timeout": {
            "value": 10,
            "required": False,
            "type": int,
            "description": "HTTP request timeout in seconds (default: 10).",
        },
    }

    def run(self) -> None:
        """Send CRLF payloads and confirm via canary response headers."""
        self.clear_findings()
        self.validate_options()

        target = self.get_option("target")
        param = self.get_option("param")
        http = self.http_client(target)

        confirmed_variants: list[str] = []
        evidence_lines: list[str] = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            task = progress.add_task(f"Testing CRLF injection on {target}", total=len(CRLF_PAYLOADS))
            self._progress = progress

            for payload, note in CRLF_PAYLOADS:
                progress.advance(task)
                # Encode control characters for the URL; keep pre-encoded
                # variants' percent signs intact.
                encoded = (
                    quote(payload, safe="%：")
                    if payload.startswith("%") or "％" in payload
                    else quote(payload)
                )
                url = f"{target}?{param}={encoded}"
                try:
                    resp = http.get(url)
                    header_value = resp.headers.get(_CANARY_NAME.lower(), "")
                    if _CANARY_VALUE in header_value:
                        confirmed_variants.append(note)
                        evidence_lines.append(
                            f"Variant '{note}': injected header {_CANARY_NAME}: {header_value}"
                        )
                        logger.warning("CRLF injection confirmed (%s)", note)
                except Exception as exc:  # noqa: BLE001 — keep scanning remaining payloads
                    logger.debug("Request error for CRLF payload '%s': %s", payload, exc)

        # One consolidated finding — the vulnerability is the same regardless
        # of which encoding variant(s) worked.
        if confirmed_variants:
            self.add_finding(
                finding_type="CRLF Injection",
                severity="MEDIUM",
                title=f"CRLF/header injection via '{param}' parameter",
                detail=(
                    f"The injected CR/LF sequence caused a new response header "
                    f"('{_CANARY_NAME}: {_CANARY_VALUE}') to appear in the HTTP response "
                    f"(working variants: {', '.join(confirmed_variants)}). "
                    f"An attacker can inject arbitrary headers (session cookies, cache "
                    f"poisoning) or split the response."
                ),
                evidence=(f"Target: {target} (parameter: {param})\n" + "\n".join(evidence_lines)),
                # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N
                cvss=6.5,
            )

        total = len(self.get_findings())
        logger.info("CRLF injection testing complete: %d finding(s).", total)
