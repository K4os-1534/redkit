"""
modules/recon/js_analyzer.py — Client-side JavaScript analyzer.

Fetches the ``<script src>`` files of the target (same-host only — the scope
guard drops third-party CDN scripts) and scans them for:

- secret patterns (AWS/Google/GitHub/Slack keys, private keys) — reported as
  HIGH *potential* with explicit manual-verification wording, since pattern
  matches can be test values or placeholders,
- exposed source maps (``.map`` files containing ``"sources"``),
- references to internal hosts (localhost, 127.0.0.1, RFC1918 ranges).

External CDNs are skipped, not followed: nothing ever leaves the target.
"""

import logging
import re
from urllib.parse import urljoin

from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from redkit.modules.base_module import BaseModule

logger = logging.getLogger(__name__)

#: pattern → (description, placeholder-aware note)
SECRET_PATTERNS: list[tuple[str, str]] = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"AIza[0-9A-Za-z_\-]{35}", "Google API key"),
    (r"sk_live_[0-9a-zA-Z]{10,}", "Stripe live secret key"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub personal access token"),
    (r"xox[baprs]-[0-9A-Za-z\-]{10,}", "Slack token"),
    (r"-----BEGIN (?:RSA )?PRIVATE KEY-----", "Embedded private key"),
]

INTERNAL_HOST_PATTERN = re.compile(
    r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)",
    re.IGNORECASE,
)

SCRIPT_SRC = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.IGNORECASE)

MAX_SCRIPTS = 10
MAX_SNIPPET = 120


class JavaScriptAnalyzer(BaseModule):
    """Analyze same-host JavaScript files for secrets, maps, and internals."""

    name = "JavaScript Analyzer"
    description = "Scans the site's JS files for exposed secrets, source maps, and internal hosts."
    author = "K4os"
    category = "recon"

    options = {
        "target": {
            "value": None,
            "required": True,
            "description": "Target URL (e.g. https://example.com).",
        },
        "timeout": {
            "value": 10,
            "required": False,
            "type": int,
            "description": "HTTP request timeout in seconds (default: 10).",
        },
    }

    def run(self) -> None:
        """Fetch the homepage, pull same-host scripts, and scan them."""
        self.clear_findings()
        self.validate_options()

        target = str(self.get_option("target")).rstrip("/")
        http = self.http_client(target)

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            task = progress.add_task(f"Analyzing JavaScript on {target}", total=None)
            self._progress = progress

            try:
                resp = http.get(target)
            except Exception as exc:  # noqa: BLE001
                logger.error("Request failed for %s: %s", target, exc)
                return

            script_urls: list[str] = []
            for raw in SCRIPT_SRC.findall(resp.text):
                absolute = urljoin(target + "/", raw)
                script_urls.append(absolute)
            script_urls = script_urls[:MAX_SCRIPTS]
            logger.info("JS analyzer: %d script(s) discovered on %s", len(script_urls), target)

            for script_url in script_urls:
                try:
                    js_resp = http.get(script_url)
                except Exception as exc:  # noqa: BLE001 — out-of-scope CDNs land here
                    logger.debug("Skipping script %s: %s", script_url, exc)
                    continue
                if js_resp.status_code != 200:
                    continue
                body = js_resp.text

                # --- Secret patterns (potential — manual verification needed) ---
                for pattern, description in SECRET_PATTERNS:
                    matches = re.findall(pattern, body)
                    if matches:
                        snippet = matches[0]
                        masked = snippet[:6] + "…" + snippet[-4:] if len(snippet) > 12 else snippet
                        logger.warning("Potential %s in %s", description, script_url)
                        self.add_finding(
                            finding_type="JavaScript Analysis",
                            severity="HIGH",
                            title=f"Potential {description} in {script_url.rsplit('/', 1)[-1]}",
                            detail=(
                                f"A value matching the {description} pattern was found in client-side "
                                f"JavaScript. Pattern matches may be placeholders or test values — "
                                f"manually verify and rotate immediately if genuine."
                            ),
                            evidence=(
                                f"GET {script_url}\nPattern: {pattern}\nMatched value (masked): {masked}"
                            ),
                            cvss=7.5,
                        )

                # --- Internal hosts ---
                internal = INTERNAL_HOST_PATTERN.findall(body)
                if internal:
                    unique = sorted(set(internal))[:5]
                    self.add_finding(
                        finding_type="JavaScript Analysis",
                        severity="INFO",
                        title=f"Internal host references in {script_url.rsplit('/', 1)[-1]}",
                        detail=(
                            "The client-side JavaScript references internal/loopback hosts. "
                            "This leaks infrastructure details and may indicate debug code in production."
                        ),
                        evidence=f"GET {script_url}\nReferences: {', '.join(unique)}",
                    )

                # --- Source maps ---
                map_match = re.search(r"//#\s*sourceMappingURL=(\S+)", body)
                map_candidates = []
                if map_match:
                    map_candidates.append(urljoin(script_url, map_match.group(1)))
                if script_url.endswith(".js"):
                    map_candidates.append(script_url + ".map")

                for map_url in map_candidates[:1]:
                    try:
                        map_resp = http.get(map_url)
                    except Exception:  # noqa: BLE001
                        continue
                    if map_resp.status_code == 200 and '"sources"' in map_resp.text:
                        self.add_finding(
                            finding_type="JavaScript Analysis",
                            severity="LOW",
                            title=f"Source map exposed: {map_url.rsplit('/', 1)[-1]}",
                            detail=(
                                "A deployable source map was found, allowing reconstruction of "
                                "the original source code of this bundle."
                            ),
                            evidence=f'GET {map_url} → HTTP 200 (contains "sources")',
                        )
                        break  # one map finding per script is enough

            progress.update(task, completed=True)

        total = len(self.get_findings())
        logger.info("JavaScript analysis complete: %d finding(s).", total)
