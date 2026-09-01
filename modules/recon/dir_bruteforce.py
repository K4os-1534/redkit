"""
modules/recon/dir_bruteforce.py — Web directory and file brute-forcing module.

Makes concurrent HTTP GET requests for each word in a wordlist (plus each
configured file extension) and records all non-404 responses as findings.
"""

import logging
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin

import requests
from requests.exceptions import RequestException
from rich.console import Console
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
console = Console()

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_DEFAULT_WORDLIST = _PROJECT_ROOT / "wordlists" / "directories.txt"

# Map HTTP status codes to Rich colour strings for live output
_STATUS_COLOURS: dict[int, str] = {
    200: "bold green",
    201: "bold green",
    204: "bold green",
    301: "bold yellow",
    302: "bold yellow",
    307: "bold yellow",
    308: "bold yellow",
    401: "bold magenta",
    403: "bold dark_orange",
    405: "bold cyan",
    500: "bold red",
}


class DirBruteforce(BaseModule):
    """Brute-force web directories and files against a target URL.

    Before scanning, a **baseline calibration** request is made to a random
    non-existent path. Its response size and status code are recorded as
    the server's custom-404 signature. Any subsequent probe that returns
    the same (status, content_length) pair is silently discarded, preventing
    servers with custom error pages from flooding findings.

    Iterates over a wordlist and optionally appends file extensions,
    recording every non-baseline, non-404 response as a finding.
    """

    name = "Directory Brute-Forcer"
    description = "Discovers hidden directories and files via HTTP brute-force."
    author = "RedKit"
    category = "recon"

    options = {
        "target": {
            "value": None,
            "required": True,
            "description": "Target base URL (e.g. https://example.com).",
        },
        "wordlist": {
            "value": str(_DEFAULT_WORDLIST),
            "required": False,
            "description": "Path to directory/file wordlist.",
        },
        "threads": {
            "value": "10",
            "required": False,
            "description": "Number of concurrent threads (default: 10).",
        },
        "timeout": {
            "value": "5",
            "required": False,
            "description": "HTTP request timeout in seconds (default: 5).",
        },
        "extensions": {
            "value": "php,html,txt",
            "required": False,
            "description": "Comma-separated list of extensions to append (e.g. php,html,txt).",
        },
    }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _load_wordlist(self, path: str) -> list[str]:
        """Read a wordlist file into a list of words.

        Args:
            path: Path to the wordlist file.

        Returns:
            List of directory/file name strings.
        """
        wl_path = Path(path)
        if not wl_path.is_file():
            logger.warning("Wordlist not found: %s", path)
            return []
        with open(wl_path, "r", encoding="utf-8", errors="ignore") as fh:
            return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

    def _build_urls(self, base: str, words: list[str], extensions: list[str]) -> list[str]:
        """Generate all URLs to probe from the wordlist and extension list.

        For each word, generates:
        - base/word  (no extension)
        - base/word.ext  (for each extension)

        Args:
            base: Base target URL.
            words: List of directory/file names.
            extensions: List of file extensions without leading dot.

        Returns:
            Deduplicated list of URLs.
        """
        urls: list[str] = []
        base = base.rstrip("/")
        for word in words:
            urls.append(f"{base}/{word}")
            for ext in extensions:
                ext = ext.strip().lstrip(".")
                if ext:
                    urls.append(f"{base}/{word}.{ext}")
        return urls

    def _get_baseline(self, base: str, timeout: int, headers: dict) -> Optional[tuple[int, int]]:
        """Probe a guaranteed non-existent path to calibrate the custom-404 signature.

        Generates a random UUID-based path that cannot realistically exist on the
        server. The returned (status, content_length) pair is then used to filter
        out identically-sized responses during the main scan.

        Args:
            base: Target base URL.
            timeout: Request timeout in seconds.
            headers: HTTP headers to include.

        Returns:
            Tuple (status_code, content_length) for the baseline response,
            or None if the baseline request itself fails.
        """
        canary = f"{base}/redkit-baseline-{uuid.uuid4().hex}"
        result = self._probe(canary, timeout, headers)
        if result:
            status, length = result
            logger.info(
                "Baseline calibration: %s → HTTP %d (%d bytes) — responses "
                "matching this signature will be filtered.",
                canary, status, length,
            )
        return result

    def _probe(self, url: str, timeout: int, headers: dict) -> Optional[tuple[int, int]]:
        """Send a GET request to a URL and return (status_code, content_length).

        Returns None if the request fails entirely.

        Args:
            url: Full URL to probe.
            timeout: Request timeout in seconds.
            headers: HTTP headers to send.

        Returns:
            Tuple (status_code, content_length) or None on error.
        """
        try:
            resp = requests.get(
                url,
                timeout=timeout,
                headers=headers,
                allow_redirects=False,
                verify=False,
            )
            return resp.status_code, len(resp.content)
        except RequestException as exc:
            logger.debug("Request failed for %s: %s", url, exc)
            return None

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Execute directory brute-forcing against the target.

        Probes each generated URL concurrently and records non-404 responses.
        """
        self.clear_findings()
        self.validate_options()

        target = self.get_option("target").rstrip("/")
        wordlist_path = self.get_option("wordlist")
        threads = int(self.get_option("threads") or 10)
        timeout = int(self.get_option("timeout") or 5)
        ext_raw = self.get_option("extensions") or ""
        extensions = [e.strip() for e in ext_raw.split(",") if e.strip()]

        # Suppress InsecureRequestWarning for self-signed certs
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        words = self._load_wordlist(wordlist_path)
        if not words:
            logger.error("Empty wordlist — aborting dir brute-force.")
            return

        from pathlib import Path as _P
        config_path = _PROJECT_ROOT / "config.yaml"
        user_agent = "RedKit/1.0 (Authorized Security Testing)"
        try:
            import yaml
            with open(config_path) as f:
                cfg = yaml.safe_load(f)
                user_agent = cfg.get("default_user_agent", user_agent)
        except Exception:
            pass

        headers = {"User-Agent": user_agent}

        # ------------------------------------------------------------------
        # Baseline calibration — detect custom 404 signature
        # ------------------------------------------------------------------
        baseline = self._get_baseline(target, timeout, headers)
        baseline_status: Optional[int] = None
        baseline_length: Optional[int] = None

        if baseline is not None:
            baseline_status, baseline_length = baseline
            # If the server properly returns 404 for the canary, no filtering
            # is needed — we already skip 404s below.
            if baseline_status == 404:
                baseline_status = None
                baseline_length = None
            else:
                console.print(
                    f"  [bold yellow][!] Custom 404 detected:[/bold yellow] "
                    f"HTTP {baseline_status} / {baseline_length} bytes — "
                    f"responses matching this signature will be filtered automatically."
                )

        urls = self._build_urls(target, words, extensions)

        logger.info(
            "Starting dir brute-force: target=%s, urls=%d, threads=%d",
            target, len(urls), threads,
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            task = progress.add_task(f"Scanning {target}", total=len(urls))

            with ThreadPoolExecutor(max_workers=threads) as executor:
                future_map = {
                    executor.submit(self._probe, url, timeout, headers): url
                    for url in urls
                }

                for future in as_completed(future_map):
                    url = future_map[future]
                    progress.advance(task)
                    try:
                        result = future.result()
                        if result is None:
                            continue
                        status, length = result

                        # Standard 404 — skip
                        if status == 404:
                            continue

                        # Custom 404 baseline filter — same status AND same
                        # content length as the canary response ⇒ skip
                        if (
                            baseline_status is not None
                            and status == baseline_status
                            and length == baseline_length
                        ):
                            continue

                        # Only surface 2xx and 3xx responses as findings.
                        # 4xx (Forbidden, Unauthorized, etc.) and 5xx (server
                        # errors) are not indicative of discovered content and
                        # would produce noise or misleading HIGH-severity hits.
                        if not (200 <= status < 400):
                            logger.debug("Skipping non-2xx/3xx response: %s → %d", url, status)
                            continue

                        colour = _STATUS_COLOURS.get(status, "white")
                        progress.console.print(
                            f"  [{colour}][{status}][/{colour}] {url} "
                            f"[dim]({length} bytes)[/dim]"
                        )

                        # Severity mapping (only 2xx/3xx reach here)
                        if status in (200, 201, 204):
                            sev = "MEDIUM"
                        elif status in (301, 302, 307, 308):
                            sev = "INFO"
                        else:
                            sev = "INFO"

                        self._add_finding(
                            finding_type="Directory/File",
                            severity=sev,
                            title=f"[{status}] {url}",
                            detail=(
                                f"HTTP {status} response received from {url}. "
                                f"Content-Length: {length} bytes."
                            ),
                            evidence=f"GET {url} → HTTP {status} ({length} bytes)",
                        )
                    except Exception as exc:  # noqa: BLE001
                        logger.debug("Error probing %s: %s", url, exc)

        total = len(self.get_findings())
        logger.info("Dir brute-force complete: %d finding(s).", total)
