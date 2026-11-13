"""
modules/vuln_scan/open_redirect_tester.py — Open redirect vulnerability tester.

Injects attacker-controlled redirect destinations into a query parameter and
flags the target as vulnerable only when the server's own ``Location`` header
points at the injected host.

The probes request with ``allow_redirects=False`` — no request is ever sent
to the injected host, so the check is both safe and false-positive free:
a ``Location`` containing ``redkit-redirect.example.net`` can only exist
because the server redirects there. Relative-hop and protocol-relative
("//host") variants are resolved against the target before comparison.
"""

import logging
from urllib.parse import urljoin, urlparse

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

# A host we control conceptually but never contact. It must differ from any
# plausible target host; only a server echo in Location can surface it.
REDIRECT_HOST = "redkit-redirect.example.net"

# (payload, note) — payload injected verbatim into the parameter.
REDIRECT_PAYLOADS: list[tuple[str, str]] = [
    (f"https://{REDIRECT_HOST}/path", "absolute URL"),
    (f"//{REDIRECT_HOST}/path", "protocol-relative URL"),
    (f"https:/{REDIRECT_HOST}/path", "single-slash variant"),
    (f"https:\\\\{REDIRECT_HOST}/path", "backslash variant"),
    (f"/\\{REDIRECT_HOST}/path", "mixed-slash relative variant"),
]


class OpenRedirectTester(BaseModule):
    """Test a query parameter for unvalidated cross-origin redirects.

    Confirmed only when the server-issued ``Location`` header resolves to
    the injected host. The probe never follows redirects, so nothing is
    ever requested from the attacker host.
    """

    name = "Open Redirect Tester"
    description = "Tests a query parameter for open redirects via Location header analysis."
    author = "K4os"
    category = "vuln_scan"

    options = {
        "target": {
            "value": None,
            "required": True,
            "description": "Target URL (e.g. https://example.com/redirect?to=/home).",
        },
        "param": {
            "value": None,
            "required": True,
            "description": "Query parameter that receives the redirect destination (e.g. to, url, next).",
        },
        "timeout": {
            "value": 10,
            "required": False,
            "type": int,
            "description": "HTTP request timeout in seconds (default: 10).",
        },
    }

    def run(self) -> None:
        """Send redirect payloads and inspect Location headers (no following)."""
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
            task = progress.add_task(f"Testing open redirects on {target}", total=len(REDIRECT_PAYLOADS))
            self._progress = progress

            for payload, note in REDIRECT_PAYLOADS:
                progress.advance(task)
                url = (
                    f"{target}&{param}={quote(payload)}"
                    if "?" in target
                    else f"{target}?{param}={quote(payload)}"
                )
                try:
                    resp = http.get(url, allow_redirects=False)
                    if not (300 <= resp.status_code < 400):
                        continue
                    location = resp.headers.get("Location", "")
                    if not location:
                        continue
                    resolved = urljoin(url, location)
                    location_host = (urlparse(resolved).hostname or "").lower()
                    if REDIRECT_HOST in location_host:
                        confirmed_variants.append(note)
                        evidence_lines.append(
                            f"Variant '{note}': HTTP {resp.status_code}, Location: {location}"
                        )
                        logger.warning("Open redirect confirmed (%s): Location=%s", note, location)
                except Exception as exc:  # noqa: BLE001 — keep scanning remaining payloads
                    logger.debug("Request error for redirect payload '%s': %s", payload, exc)

        # One consolidated finding — the vulnerability is the same regardless
        # of which payload variant reached the injected host.
        if confirmed_variants:
            self.add_finding(
                finding_type="Open Redirect",
                severity="HIGH",
                title=f"Open redirect via '{param}' parameter",
                detail=(
                    f"The application redirects to a server-controlled destination: injecting "
                    f"the probe host into '{param}' produced redirect responses whose Location "
                    f"header points at '{REDIRECT_HOST}' "
                    f"(working variants: {', '.join(confirmed_variants)}). An attacker can "
                    f"abuse this to redirect users to malicious sites (phishing, token "
                    f"leakage via redirect chains)."
                ),
                evidence=(f"Target: {target} (parameter: {param})\n" + "\n".join(evidence_lines)),
                # CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N
                cvss=6.1,
            )

        total = len(self.get_findings())
        logger.info("Open redirect testing complete: %d finding(s).", total)
