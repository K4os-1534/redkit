"""
modules/misconfig/graphql_introspection.py — GraphQL introspection tester.

POSTs a minimal introspection query to common GraphQL endpoints and reports
introspection as enabled only when the canonical ``{"data":{"__schema": …}}``
envelope is returned — request bodies are never echoed by JSON APIs, so
reflection cannot trigger a false positive. Endpoints that exist but reject
introspection are reported as INFO (endpoint discovered, hardening present).
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

GRAPHQL_PATHS = ["graphql", "api/graphql", "graphql/v1", "v1/graphql", "graphiql"]

INTROSPECTION_QUERY = '{"query":"{ __schema { queryType { name } } }"}'


class GraphqlIntrospection(BaseModule):
    """Detect GraphQL endpoints and test whether introspection is enabled."""

    name = "GraphQL Introspection"
    description = "Finds GraphQL endpoints and tests if introspection is enabled."
    author = "K4os"
    category = "misconfig"

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

    def run(self) -> None:
        """Probe GraphQL paths with an introspection query."""
        self.clear_findings()
        self.validate_options()

        target = self.get_option("target").rstrip("/")
        http = self.http_client(target)

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            task = progress.add_task(f"Probing GraphQL endpoints on {target}", total=len(GRAPHQL_PATHS))
            self._progress = progress

            for path in GRAPHQL_PATHS:
                progress.advance(task)
                url = f"{target}/{path}"
                try:
                    resp = http.post(
                        url,
                        data=INTROSPECTION_QUERY,
                        headers={"Content-Type": "application/json"},
                    )
                except Exception as exc:  # noqa: BLE001 — keep probing remaining paths
                    logger.debug("Request error for GraphQL path '%s': %s", path, exc)
                    continue

                body = resp.text
                if '"data"' in body and "__schema" in body and '"queryType"' in body:
                    logger.warning("GraphQL introspection enabled at /%s", path)
                    self.add_finding(
                        finding_type="GraphQL",
                        severity="MEDIUM",
                        title=f"GraphQL introspection enabled: /{path}",
                        detail=(
                            f"The GraphQL endpoint /{path} answered an introspection query with the "
                            f"full schema metadata. Introspection exposes every type, field, and "
                            f"mutation — a complete API map for attackers."
                        ),
                        evidence=(
                            f"POST {url}\nQuery: {INTROSPECTION_QUERY}\n"
                            f"Response: HTTP {resp.status_code} — __schema/queryType present\n"
                            f"Response snippet: {body[:300]}"
                        ),
                        cvss=5.3,
                    )
                elif resp.status_code == 200 and (
                    "graphql" in body.lower() or "cannot query" in body.lower()
                ):
                    # Endpoint exists but rejected introspection — hardening works.
                    logger.info("GraphQL endpoint found (introspection disabled): /%s", path)
                    self.add_finding(
                        finding_type="GraphQL",
                        severity="INFO",
                        title=f"GraphQL endpoint found (introspection disabled): /{path}",
                        detail=(
                            f"A GraphQL endpoint is reachable at /{path}, but the introspection "
                            f"query was rejected — schema disclosure is prevented."
                        ),
                        evidence=f"POST {url} → HTTP {resp.status_code}\nResponse snippet: {body[:200]}",
                    )

        total = len(self.get_findings())
        logger.info("GraphQL testing complete: %d finding(s).", total)
