"""
modules/misconfig/cors_auditor.py — CORS misconfiguration tester.

Sends requests with attacker-controlled ``Origin`` headers and confirms
misconfiguration **only when the server reflects the exact injected origin**
into ``Access-Control-Allow-Origin`` (or returns a wildcard alongside
``Access-Control-Allow-Credentials``). Exact-echo matching means a benign
CORS policy can never trigger a finding.

Reflection with credentials is HIGH; reflection without credentials and
``Origin: null`` reflection are MEDIUM.
"""

import logging

from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from redkit.modules.base_module import BaseModule

logger = logging.getLogger(__name__)

ATTACKER_ORIGIN = "https://redkit-cors.example.net"


class CorsAuditor(BaseModule):
    """Test an endpoint for dangerous CORS policies via Origin reflection."""

    name = "CORS Tester"
    description = "Tests endpoints for origin-reflection and wildcard CORS misconfigurations."
    author = "K4os"
    category = "misconfig"

    options = {
        "target": {
            "value": None,
            "required": True,
            "description": "API endpoint to test (e.g. https://example.com/api/user).",
        },
        "timeout": {
            "value": 10,
            "required": False,
            "type": int,
            "description": "HTTP request timeout in seconds (default: 10).",
        },
    }

    def run(self) -> None:
        """Probe with crafted Origin headers and verify exact reflection."""
        self.clear_findings()
        self.validate_options()

        target = self.get_option("target")
        http = self.http_client(target)

        probes = [
            ({"Origin": ATTACKER_ORIGIN}, "origin reflection", True),
            ({"Origin": "null"}, "null-origin allowance", False),
        ]

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            task = progress.add_task(f"Testing CORS on {target}", total=len(probes))
            self._progress = progress

            for headers, note, allow_credentials_check in probes:
                progress.advance(task)
                try:
                    resp = http.get(target, headers=headers)
                except Exception as exc:  # noqa: BLE001 — keep probing
                    logger.debug("Request error for CORS probe '%s': %s", note, exc)
                    continue

                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

                if not acao:
                    continue

                if acao.strip() == ATTACKER_ORIGIN and allow_credentials_check:
                    with_creds = acac == "true"
                    self.add_finding(
                        finding_type="CORS",
                        severity="HIGH" if with_creds else "MEDIUM",
                        title=f"CORS reflects arbitrary origin ({note})"
                        + (" with credentials" if with_creds else ""),
                        detail=(
                            f"The endpoint reflected the attacker-controlled Origin "
                            f"'{ATTACKER_ORIGIN}' back in Access-Control-Allow-Origin"
                            + (
                                " together with Access-Control-Allow-Credentials: true, "
                                "allowing any website to read authenticated responses."
                                if with_creds
                                else ", allowing any website to read the response."
                            )
                        ),
                        evidence=(
                            f"GET {target}\nOrigin: {ATTACKER_ORIGIN}\n"
                            f"Access-Control-Allow-Origin: {acao}\n"
                            f"Access-Control-Allow-Credentials: {acac or '(absent)'}"
                        ),
                        # CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N (credentialed read)
                        cvss=7.1 if with_creds else 5.3,
                    )
                elif acao.strip() == "null" and note == "null-origin allowance":
                    self.add_finding(
                        finding_type="CORS",
                        severity="MEDIUM",
                        title="CORS allows the null origin",
                        detail=(
                            "The endpoint returns Access-Control-Allow-Origin: null, which "
                            "sandboxed iframes and certain XSS payloads can leverage to read "
                            "responses cross-origin."
                        ),
                        evidence=(f"GET {target}\nOrigin: null\nAccess-Control-Allow-Origin: {acao}"),
                        cvss=5.3,
                    )
                elif acao.strip() == "*" and acac == "true":
                    self.add_finding(
                        finding_type="CORS",
                        severity="HIGH",
                        title="CORS wildcard combined with credentials",
                        detail=(
                            "Access-Control-Allow-Origin: * is combined with "
                            "Access-Control-Allow-Credentials: true. Most browsers reject this "
                            "combination, but non-browser clients and proxies may not — the "
                            "intent signals a misconfigured policy."
                        ),
                        evidence=(
                            f"GET {target}\n"
                            f"Access-Control-Allow-Origin: *\n"
                            f"Access-Control-Allow-Credentials: true"
                        ),
                        cvss=7.1,
                    )

        total = len(self.get_findings())
        logger.info("CORS testing complete: %d finding(s).", total)
