"""
modules/misconfig/api_docs.py — Exposed API documentation tester.

Probes common documentation endpoints (Swagger UI, OpenAPI JSON, API blueprint
pages) and confirms findings through content signatures — OpenAPI/Swagger
JSON structure keys or the Swagger UI title — so a page merely mentioning
"api" can never fire, and soft-404 SPAs are filtered by the canary baseline.
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

#: path → confirm signatures (any match; case-insensitive).
DOC_PATHS: dict[str, list[str]] = {
    "swagger.json": ['"swagger"', '"openapi"'],
    "openapi.json": ['"openapi"', '"swagger"'],
    "api-docs": ["swagger-ui", "swagger ui", '"swagger"', '"openapi"'],
    "api-docs/swagger.json": ['"swagger"', '"openapi"'],
    "api/openapi.json": ['"openapi"'],
    "swagger": ["swagger-ui", "swagger ui"],
    "docs": ["redoc", "swagger-ui", '"openapi"'],
}


class ApiDocsExposure(BaseModule):
    """Detect exposed API documentation endpoints (signature-confirmed)."""

    name = "API Docs Exposure"
    description = "Detects exposed Swagger/OpenAPI documentation endpoints — signature confirmed."
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
        except Exception as exc:  # noqa: BLE001
            logger.debug("Request failed for %s: %s", url, exc)
            return None

    def run(self) -> None:
        """Probe documentation paths with signature confirmation."""
        self.clear_findings()
        self.validate_options()

        target = self.get_option("target").rstrip("/")
        threads = int(self.get_option("threads") or 5)
        http = self.http_client(target)

        # Soft-404 baseline — SPAs frequently return 200 + index.html everywhere.
        baseline = self._probe(http, f"{target}/redkit-baseline-{uuid.uuid4().hex}")
        baseline_status, baseline_length = (baseline[0], baseline[1]) if baseline else (None, None)
        if baseline is not None and baseline_status == 404:
            baseline_status, baseline_length = None, None

        paths = list(DOC_PATHS.keys())

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            task = progress.add_task(f"Probing API docs on {target}", total=len(paths))
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
                        if (
                            baseline_status is not None
                            and status == baseline_status
                            and length == baseline_length
                        ):
                            continue
                        if not (200 <= status < 400):
                            continue

                        body_lower = body.lower()
                        if not any(sig in body_lower for sig in DOC_PATHS[path]):
                            continue

                        logger.warning("API documentation exposed: /%s", path)
                        self.add_finding(
                            finding_type="API Documentation",
                            severity="MEDIUM",
                            title=f"API documentation exposed: /{path}",
                            detail=(
                                f"API documentation is publicly accessible at /{path}. It discloses "
                                f"the complete API surface — endpoints, parameters, and data models — "
                                f"significantly easing attacker reconnaissance."
                            ),
                            evidence=f"GET {target}/{path} → HTTP {status} ({length} bytes)",
                            cvss=5.3,
                        )
                    except Exception as exc:  # noqa: BLE001
                        logger.debug("Error probing %s: %s", path, exc)

        total = len(self.get_findings())
        logger.info("API docs testing complete: %d finding(s).", total)
