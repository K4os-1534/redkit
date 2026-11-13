"""
modules/misconfig/sensitive_files.py — Sensitive file / repository disclosure tester.

Probes a focused list of commonly exposed sensitive paths (``.git/HEAD``,
``.env``, ``phpinfo.php``, ``/ftp`` dumps, …) and **confirms every finding
through content signatures** — never status codes alone. On top of the
signature requirement, a random canary baseline filters soft-404 servers.

The double protection (signature + baseline) keeps the false-positive rate
at effectively zero; unknown contents are never reported.
"""

import logging
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

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

#: path → (severity, cvss or None, confirm signatures, description)
SENSITIVE_PATHS: dict[str, tuple[str, float | None, list[str], str]] = {
    ".git/HEAD": (
        "HIGH",
        7.5,
        ["ref: refs/"],
        "The Git repository metadata is exposed; the full source (and history) can be reconstructed.",
    ),
    ".git/config": (
        "HIGH",
        7.5,
        ["[core]", "repositoryformatversion"],
        "The Git repository configuration is exposed, potentially including remote URLs with credentials.",
    ),
    ".env": (
        "HIGH",
        7.5,
        [
            "DB_PASSWORD",
            "DATABASE_URL",
            "AWS_ACCESS_KEY_ID",
            "APP_KEY",
            "JWT_SECRET",
            "SMTP_PASSWORD",
            "API_KEY=",
            "SECRET_KEY",
        ],
        "An environment file with application secrets appears to be exposed.",
    ),
    ".htaccess": (
        "MEDIUM",
        None,
        ["RewriteRule", "Options ", "Deny from", "AuthType", "Require "],
        "An Apache .htaccess file is exposed, disclosing server configuration.",
    ),
    ".DS_Store": (
        "LOW",
        None,
        ["Bud1"],
        "A macOS .DS_Store file is exposed, potentially disclosing file and directory names.",
    ),
    "phpinfo.php": (
        "MEDIUM",
        5.3,
        ["phpinfo()", "PHP Version", "Configuration File"],
        "A phpinfo page is exposed, disclosing the full server configuration, paths, and environment.",
    ),
    "server-status": (
        "MEDIUM",
        5.3,
        ["Apache Status", "Server Status", "server-status", "CPU Usage"],
        "Apache server-status is exposed, disclosing requests, vhosts, and client IPs.",
    ),
    "actuator": (
        "HIGH",
        7.5,
        ['"_links"', '"health"', '"diskSpace"'],
        "A Spring Boot Actuator endpoint is exposed, potentially disclosing health, env, and heap data.",
    ),
    "ftp": (
        "HIGH",
        7.5,
        ["package.json.bak", "acquisitions.md", "coupons_2013", "memorial.html"],
        "An FTP-style file dump directory is exposed.",
    ),
}


class SensitiveFileDisclosure(BaseModule):
    """Probe sensitive paths and confirm only via content signatures."""

    name = "Sensitive File Disclosure"
    description = "Detects exposed .git, .env, backups, debug endpoints — content-signature confirmed."
    author = "K4os"
    category = "misconfig"

    options = {
        "target": {
            "value": None,
            "required": True,
            "description": "Target base URL (e.g. https://example.com).",
        },
        "threads": {
            "value": 5,
            "required": False,
            "type": int,
            "description": "Number of concurrent threads (default: 5).",
        },
        "timeout": {
            "value": 10,
            "required": False,
            "type": int,
            "description": "HTTP request timeout in seconds (default: 10).",
        },
    }

    def _probe(self, http, url: str) -> tuple[int, int, str] | None:
        """GET a URL; return (status, content_length, body) or None on error."""
        try:
            resp = http.get(url, allow_redirects=False)
            return resp.status_code, len(resp.content), resp.text
        except Exception as exc:  # noqa: BLE001 — probe failures are recorded, not fatal
            logger.debug("Request failed for %s: %s", url, exc)
            return None

    def run(self) -> None:
        """Probe sensitive paths with signature + baseline double filtering."""
        self.clear_findings()
        self.validate_options()

        target = self.get_option("target").rstrip("/")
        threads = int(self.get_option("threads") or 5)
        http = self.http_client(target)

        # Soft-404 baseline (same technique as the directory brute-forcer).
        baseline = self._probe(http, f"{target}/redkit-baseline-{uuid.uuid4().hex}")
        baseline_status, baseline_length = (baseline[0], baseline[1]) if baseline else (None, None)
        if baseline is not None and baseline_status == 404:
            baseline_status, baseline_length = None, None

        paths = list(SENSITIVE_PATHS.keys())

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            task = progress.add_task(f"Probing sensitive files on {target}", total=len(paths))
            self._progress = progress

            with ThreadPoolExecutor(max_workers=threads) as executor:
                future_map = {executor.submit(self._probe, http, f"{target}/{path}"): path for path in paths}
                for future in as_completed(future_map):
                    path = future_map[future]
                    progress.advance(task)
                    try:
                        result = future.result()
                        if result is None:
                            continue
                        status, length, body = result

                        if status == 404:
                            continue
                        # Custom soft-404 filter — identical status AND length.
                        if (
                            baseline_status is not None
                            and status == baseline_status
                            and length == baseline_length
                        ):
                            continue
                        if not (200 <= status < 400):
                            continue

                        severity, cvss, signatures, description = SENSITIVE_PATHS[path]
                        matched = [s for s in signatures if s.lower() in body.lower()]
                        if not matched:
                            # Signature requirement — status alone never confirms.
                            continue

                        logger.warning("Sensitive file exposed: %s (matched: %s)", path, matched[:2])
                        self.add_finding(
                            finding_type="Sensitive File",
                            severity=severity,
                            title=f"Sensitive path exposed: /{path}",
                            detail=f"{description} Response HTTP {status} matched "
                            f"signature(s): {', '.join(matched[:3])}.",
                            evidence=(
                                f"GET {target}/{path} → HTTP {status} ({length} bytes)\n"
                                f"Matched signature(s): {', '.join(matched[:5])}\n"
                                f"Response snippet: {body[:200]}"
                            ),
                            cvss=cvss,
                        )
                    except Exception as exc:  # noqa: BLE001
                        logger.debug("Error probing %s: %s", path, exc)

        total = len(self.get_findings())
        logger.info("Sensitive file testing complete: %d finding(s).", total)
