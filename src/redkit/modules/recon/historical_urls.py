"""
modules/recon/historical_urls.py — Historical URL discovery via the Wayback CDX API.

Queries the Internet Archive's CDX API for URLs previously seen on the
target domain and reports them as a single aggregated INFO finding (with a
sample in the evidence) — one finding instead of hundreds of rows keeps the
findings table readable.

Only the target *domain name* is sent to web.archive.org; no request touches
the target itself. The module runs unscoped by design, degrades gracefully
when the archive is unreachable, and is informational only.
"""

import logging
from urllib.parse import urlparse

from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from redkit.modules.base_module import BaseModule

logger = logging.getLogger(__name__)

CDX_URL = "https://web.archive.org/cdx/search/cdx"
DEFAULT_MAX_URLS = 200
SAMPLE_SIZE = 25


class HistoricalUrls(BaseModule):
    """Discover historical endpoints via the Wayback Machine CDX API."""

    name = "Historical URLs (Wayback)"
    description = "Lists historical URLs for the domain via the archive.org CDX API (informational)."
    author = "K4os"
    category = "recon"

    options = {
        "target": {
            "value": None,
            "required": True,
            "description": "Target URL or domain (e.g. https://example.com).",
        },
        "max_urls": {
            "value": DEFAULT_MAX_URLS,
            "required": False,
            "type": int,
            "description": f"Maximum URLs to request from the CDX API (default: {DEFAULT_MAX_URLS}).",
        },
        "timeout": {
            "value": 30,
            "required": False,
            "type": int,
            "description": "HTTP request timeout in seconds (default: 30 — the archive can be slow).",
        },
    }

    def run(self) -> None:
        """Query the CDX API and aggregate historical URLs into one finding."""
        self.clear_findings()
        self.validate_options()

        target = str(self.get_option("target"))
        host = urlparse(target if "://" in target else f"https://{target}").hostname
        if not host:
            logger.error("Could not determine domain from target '%s'.", target)
            return
        max_urls = int(self.get_option("max_urls") or DEFAULT_MAX_URLS)
        timeout = int(self.get_option("timeout") or 30)

        # Unscoped client BY DESIGN: the request goes to web.archive.org, not
        # to the target. Only the domain name leaves the machine.
        http = self.http_client(enforce_scope=False)

        url = (
            f"{CDX_URL}?url={host}/*&output=json&collapse=urlkey"
            f"&fl=original&limit={max_urls}&filter=statuscode:200"
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            task = progress.add_task(f"Querying Wayback CDX for {host}", total=None)
            self._progress = progress

            try:
                resp = http.get(url, timeout=timeout)
            except Exception as exc:  # noqa: BLE001 — archive unreachable is not fatal
                logger.warning("Wayback CDX request failed — skipping historical URLs: %s", exc)
                return

            if resp.status_code != 200:
                logger.warning("Wayback CDX returned HTTP %d — skipping.", resp.status_code)
                return

            import json

            try:
                rows = json.loads(resp.text)
            except ValueError:
                logger.warning("Wayback CDX returned non-JSON output — skipping.")
                return

            historical: list[str] = []
            if isinstance(rows, list) and len(rows) > 1:
                for row in rows[1:]:  # row 0 is the header
                    if row and isinstance(row[0], str):
                        historical.append(row[0])

            if not historical:
                logger.info("No historical URLs found for %s.", host)
                return

            sample = "\n".join(historical[:SAMPLE_SIZE])
            logger.info("Historical URLs: %d found for %s", len(historical), host)
            self.add_finding(
                finding_type="Historical URLs",
                severity="INFO",
                title=f"{len(historical)} historical URLs known for {host}",
                detail=(
                    f"The Wayback Machine has previously archived {len(historical)} URL(s) on "
                    f"{host}. Old endpoints may still resolve — verify that retired URLs do not "
                    f"expose stale data or bypass current authentication."
                ),
                evidence=(
                    f"Source: web.archive.org CDX (query: {host}/*)\n"
                    f"Sample of {min(SAMPLE_SIZE, len(historical))} URLs:\n{sample}"
                ),
            )

            progress.update(task, completed=True)

        logger.info("Historical URL discovery complete.")
