"""
modules/vuln_scan/cmd_injection_tester.py — Blind OS command injection tester.

Injects time-delay shell payloads (Unix ``sleep`` and Windows ``ping``) into
a query parameter and applies the same false-positive controls as the SQLi
tester: baseline latency calibration, an adaptive threshold, and a
re-verification request — only reproducible delays are reported as CRITICAL.
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

# (payload, shell family) — each should stall a vulnerable server ~5–6s.
CMD_PAYLOADS: list[tuple[str, str]] = [
    ("; sleep 6", "Unix (;)"),
    ("| sleep 6", "Unix (|)"),
    ("&& sleep 6", "Unix (&&)"),
    ("`sleep 6`", "Unix (backticks)"),
    ("$(sleep 6)", "Unix ($())"),
    ("& ping -n 6 127.0.0.1 >nul", "Windows (ping)"),
]

TIME_THRESHOLD: float = 4.5
BASELINE_SAMPLES: int = 2
BASELINE_TIME_FACTOR: float = 3.0


class CmdInjectionTester(BaseModule):
    """Test a query parameter for blind OS command injection via time delays.

    Re-verification is mandatory: a single slow response is reported as INFO
    (likely latency), while a reproducible delay is CRITICAL.
    """

    name = "Command Injection Tester"
    description = "Tests a query parameter for blind command injection via time-delay payloads."
    author = "K4os"
    category = "vuln_scan"

    options = {
        "target": {
            "value": None,
            "required": True,
            "description": "Target URL (e.g. https://example.com/ping?host=).",
        },
        "param": {
            "value": None,
            "required": True,
            "description": "Query parameter name to inject into (e.g. host, ip, cmd).",
        },
        "timeout": {
            "value": 15,
            "required": False,
            "type": int,
            "description": "HTTP request timeout in seconds (default: 15).",
        },
    }

    def _retest(self, http: HttpClient, url: str, threshold: float) -> float | None:
        """Re-send a slow payload once; return the elapsed time if reproducible."""
        try:
            start = time.monotonic()
            http.get(url)
            elapsed = time.monotonic() - start
        except Exception:  # noqa: BLE001 — a failed retest is simply "not confirmed"
            return None
        return elapsed if elapsed >= threshold else None

    def run(self) -> None:
        """Send time-delay payloads with baseline calibration and retest."""
        self.clear_findings()
        self.validate_options()

        target = self.get_option("target")
        param = self.get_option("param")
        http = self.http_client(target)

        confirmed: list[tuple[str, float, float]] = []
        one_offs: list[tuple[str, float]] = []
        seen_slow: set[str] = set()

        # Baseline calibration — identical to the SQLi module's approach.
        benign_url = f"{target}?{param}=redkit-baseline-probe"
        baseline_time = 0.0
        try:
            baseline_times: list[float] = []
            for _ in range(BASELINE_SAMPLES):
                start = time.monotonic()
                http.get(benign_url)
                baseline_times.append(time.monotonic() - start)
            baseline_time = max(baseline_times)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Baseline request failed — timing baseline unavailable: %s", exc)

        time_threshold = max(TIME_THRESHOLD, baseline_time * BASELINE_TIME_FACTOR)
        logger.info(
            "Command injection testing: target=%s, param=%s, payloads=%d, threshold=%.2fs",
            target,
            param,
            len(CMD_PAYLOADS),
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
            task = progress.add_task(f"Testing command injection on {target}", total=len(CMD_PAYLOADS))
            self._progress = progress

            for payload, family in CMD_PAYLOADS:
                progress.advance(task)
                url = f"{target}?{param}={quote(payload)}"
                try:
                    start = time.monotonic()
                    http.get(url)
                    elapsed = time.monotonic() - start

                    if elapsed >= time_threshold and payload not in seen_slow:
                        seen_slow.add(payload)
                        retest = self._retest(http, url, time_threshold)
                        if retest is not None:
                            confirmed.append((family, elapsed, retest))
                            logger.warning(
                                "Command injection confirmed (%s): %.2fs / %.2fs",
                                family,
                                elapsed,
                                retest,
                            )
                        else:
                            one_offs.append((payload, elapsed))
                            logger.info("One-off slow response for '%s' — reported as INFO.", payload)
                except Exception as exc:  # noqa: BLE001 — keep scanning remaining payloads
                    logger.debug("Request error for command injection payload '%s': %s", payload, exc)

        # One consolidated CRITICAL finding when any delay reproduced.
        if confirmed:
            families = ", ".join(family for family, _t1, _t2 in confirmed)
            timings = "; ".join(f"{family}: {t1:.2f}s/{t2:.2f}s" for family, t1, t2 in confirmed)
            self.add_finding(
                finding_type="Command Injection",
                severity="CRITICAL",
                title="Blind OS command injection detected",
                detail=(
                    f"Reproducible time delays were observed via the '{param}' parameter "
                    f"(families: {families}; threshold {time_threshold:.2f}s, baseline "
                    f"{baseline_time:.2f}s). The parameter appears to be passed to an OS shell "
                    f"where the injected time-delay command is executed."
                ),
                evidence=(
                    f"Target: {target} (parameter: {param})\nResponse times (request/retest): {timings}"
                ),
                # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
                cvss=9.8,
            )
        elif one_offs:
            listing = "; ".join(f"{payload} ({elapsed:.2f}s)" for payload, elapsed in one_offs)
            self.add_finding(
                finding_type="Command Injection",
                severity="INFO",
                title="Possible blind command injection (not reproducible)",
                detail=(
                    f"A single response per payload exceeded the time threshold "
                    f"({time_threshold:.2f}s, baseline {baseline_time:.2f}s) but the delays did "
                    f"not reproduce on retest. Likely server latency — manual verification advised."
                ),
                evidence=(f"Target: {target} (parameter: {param})\nOne-off slow payloads: {listing}"),
            )

        total = len(self.get_findings())
        logger.info("Command injection testing complete: %d finding(s).", total)
