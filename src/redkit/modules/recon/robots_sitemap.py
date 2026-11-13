"""
modules/recon/robots_sitemap.py — robots.txt and sitemap.xml harvester.

Fetches ``/robots.txt`` and ``/sitemap.xml`` and reports discovered paths as
INFO findings. Soft-404 SPAs are filtered by a content check: a robots.txt
must actually contain directives (User-agent/Disallow/Sitemap), otherwise it
is treated as a not-found page — a plain 200 is never enough.

Results can later inform directory brute-forcing wordlists.
"""

import logging
import re
from urllib.parse import urlparse

from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from redkit.modules.base_module import BaseModule

logger = logging.getLogger(__name__)

MAX_PATHS = 50

SITEMAP_LOC = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.IGNORECASE | re.DOTALL)


class RobotsSitemapHarvester(BaseModule):
    """Harvest hidden paths from robots.txt and sitemap.xml."""

    name = "robots.txt & Sitemap Harvester"
    description = "Extracts hidden paths from robots.txt and sitemap.xml files."
    author = "K4os"
    category = "recon"

    options = {
        "target": {
            "value": None,
            "required": True,
            "description": "Target base URL (e.g. https://example.com).",
        },
        "timeout": {
            "value": 10,
            "required": False,
            "type": int,
            "description": "HTTP request timeout in seconds (default: 10).",
        },
    }

    def _fetch(self, http, url: str) -> str | None:
        """GET a URL, returning the body only for 2xx responses."""
        try:
            resp = http.get(url, allow_redirects=False)
            if 200 <= resp.status_code < 300:
                return resp.text
            return None
        except Exception as exc:  # noqa: BLE001
            logger.debug("Request failed for %s: %s", url, exc)
            return None

    def run(self) -> None:
        """Harvest robots.txt directives and sitemap URLs."""
        self.clear_findings()
        self.validate_options()

        target = str(self.get_option("target")).rstrip("/")
        base_host = urlparse(target).hostname or target
        http = self.http_client(target)

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            task = progress.add_task(f"Harvesting robots.txt / sitemap on {target}", total=None)
            self._progress = progress

            disallowed: list[str] = []
            sitemap_urls: list[str] = []

            # --- robots.txt ---
            robots = self._fetch(http, f"{target}/robots.txt")
            if robots and re.search(r"user-agent|disallow|sitemap|allow:", robots, re.IGNORECASE):
                for line in robots.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            disallowed.append(path)
                    elif line.lower().startswith("sitemap:"):
                        sitemap_urls.append(line.split(":", 1)[1].strip())

                self.add_finding(
                    finding_type="robots.txt",
                    severity="INFO",
                    title=f"robots.txt found ({len(disallowed)} Disallow entries)",
                    detail=(
                        f"robots.txt at {target}/robots.txt discloses {len(disallowed)} "
                        f"Disallowed path(s). These are intentionally hidden but public — "
                        f"verify each requires authentication."
                    ),
                    evidence=(
                        f"robots.txt ({len(robots)} bytes)\n"
                        + "\n".join(f"Disallow: {p}" for p in disallowed[:MAX_PATHS])
                    ),
                )
            elif robots is not None:
                logger.info("robots.txt exists but contains no directives — treated as soft-404.")

            # --- sitemap.xml (from robots' Sitemap: lines or the default path) ---
            candidates = sitemap_urls[:3] or [f"{target}/sitemap.xml"]
            locations: list[str] = []
            for sitemap_url in candidates:
                body = self._fetch(http, sitemap_url)
                if not body or "<loc>" not in body.lower():
                    continue
                locations = SITEMAP_LOC.findall(body)[:MAX_PATHS]
                if locations:
                    self.add_finding(
                        finding_type="robots.txt",
                        severity="INFO",
                        title=f"sitemap.xml found ({len(locations)} URLs): {sitemap_url}",
                        detail=(
                            f"A sitemap at {sitemap_url} discloses {len(locations)} URL(s), "
                            f"revealing endpoints and content structure."
                        ),
                        evidence="\n".join(locations[:MAX_PATHS]),
                    )
                    break

            if not disallowed and not locations:
                logger.info("No robots.txt directives or sitemap found for %s.", base_host)

            progress.update(task, completed=True)

        total = len(self.get_findings())
        logger.info("robots/sitemap harvest complete: %d finding(s).", total)
