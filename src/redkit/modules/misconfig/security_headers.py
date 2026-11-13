"""
modules/misconfig/security_headers.py — HTTP security header auditor.

Performs a single GET request and reports missing or weak hardening headers:
Content-Security-Policy, Strict-Transport-Security (HTTPS only),
X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and
Permissions-Policy.

Presence checks are deterministic — there is no heuristics layer to cause
false positives.
"""

import logging

from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from redkit.modules.base_module import BaseModule

logger = logging.getLogger(__name__)

#: header (lowercase), title, severity, detail-template, minimum for HSTS.
HEADER_CHECKS: list[dict[str, object]] = [
    {
        "header": "content-security-policy",
        "title": "Missing Content-Security-Policy",
        "severity": "MEDIUM",
        "detail": (
            "No Content-Security-Policy header was returned. CSP is the primary "
            "mitigation against cross-site scripting and data-injection attacks."
        ),
    },
    {
        "header": "strict-transport-security",
        "title": "Missing Strict-Transport-Security (HSTS)",
        "severity": "MEDIUM",
        "detail": (
            "The HTTPS endpoint does not return an HSTS header, allowing "
            "ssl-strip and downgrade attacks on first-time visitors."
        ),
        "https_only": True,
    },
    {
        "header": "x-frame-options",
        "title": "Missing X-Frame-Options / frame-ancestors",
        "severity": "LOW",
        "detail": (
            "Neither X-Frame-Options nor a CSP frame-ancestors directive was "
            "returned — the page can be framed and is exposed to clickjacking."
        ),
    },
    {
        "header": "x-content-type-options",
        "title": "Missing X-Content-Type-Options",
        "severity": "LOW",
        "detail": (
            "The nosniff header is absent, allowing MIME-type sniffing which "
            "can turn uploaded content into executable scripts."
        ),
    },
    {
        "header": "referrer-policy",
        "title": "Missing Referrer-Policy",
        "severity": "LOW",
        "detail": (
            "No Referrer-Policy was returned; full URLs (including query "
            "strings with tokens) may leak to third-party sites via Referer."
        ),
    },
    {
        "header": "permissions-policy",
        "title": "Missing Permissions-Policy",
        "severity": "INFO",
        "detail": (
            "No Permissions-Policy was returned; powerful browser features "
            "(camera, geolocation, …) are not explicitly restricted."
        ),
    },
]

HSTS_MIN_MAX_AGE = 15768000  # six months


class SecurityHeadersAuditor(BaseModule):
    """Audit a single response for missing/weak security hardening headers."""

    name = "Security Headers Auditor"
    description = "Audits missing or weak HTTP security hardening headers."
    author = "K4os"
    category = "misconfig"

    options = {
        "target": {
            "value": None,
            "required": True,
            "description": "Target URL to audit (e.g. https://example.com/).",
        },
        "timeout": {
            "value": 10,
            "required": False,
            "type": int,
            "description": "HTTP request timeout in seconds (default: 10).",
        },
    }

    def run(self) -> None:
        """Fetch the target once and report header gaps."""
        self.clear_findings()
        self.validate_options()

        target = self.get_option("target")
        http = self.http_client(target)

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            task = progress.add_task(f"Auditing security headers on {target}", total=None)
            self._progress = progress

            try:
                resp = http.get(target)
            except Exception as exc:  # noqa: BLE001 — network failures end the audit
                logger.error("Request failed for %s: %s", target, exc)
                return

            headers = {k.lower(): v for k, v in resp.headers.items()}
            scheme = target.split("://", 1)[0].lower()

            for check in HEADER_CHECKS:
                header = str(check["header"])
                https_only = bool(check.get("https_only", False))
                if https_only and scheme != "https":
                    continue

                value = headers.get(header)
                if value:
                    # HSTS present but too short is still a finding.
                    if header == "strict-transport-security":
                        max_age = 0
                        for part in value.split(";"):
                            part = part.strip().lower()
                            if part.startswith("max-age="):
                                try:
                                    max_age = int(part.split("=", 1)[1])
                                except ValueError:
                                    max_age = 0
                        if max_age >= HSTS_MIN_MAX_AGE:
                            continue
                        self.add_finding(
                            finding_type="Security Headers",
                            severity="LOW",
                            title="Weak HSTS max-age",
                            detail=(
                                f"Strict-Transport-Security max-age is {max_age}s — below the "
                                f"recommended {HSTS_MIN_MAX_AGE}s (six months). Users may be "
                                f"exposed to downgrade attacks after cache expiry."
                            ),
                            evidence=f"Strict-Transport-Security: {value}",
                        )
                    continue

                self.add_finding(
                    finding_type="Security Headers",
                    severity=str(check["severity"]),
                    title=str(check["title"]),
                    detail=str(check["detail"]),
                    evidence=f"Missing response header: {header} (HTTP {resp.status_code})",
                )

            progress.update(task, completed=True)

        total = len(self.get_findings())
        logger.info("Security headers audit complete: %d finding(s).", total)
