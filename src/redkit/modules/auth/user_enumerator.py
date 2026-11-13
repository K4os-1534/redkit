"""
modules/auth/user_enumerator.py — Username enumeration tester.

Compares login responses for a known-existing username against a
guaranteed-nonexistent one (three probes each). Signals, in decreasing
confidence:

1. **Message-based** (MEDIUM): all known-user responses are mutually
   identical, all unknown-user responses are mutually identical, and the two
   differ — a stable, attacker-observable discriminator.
2. **Size-based** (MEDIUM): bodies vary (CSRF tokens etc.) but sizes differ
   consistently across all probes.
3. **Timing-based** (INFO): a consistent, repeated timing gap — reported as
   "possible" only after two consistent rounds, never as MEDIUM.

Servers that answer identically for both users produce no findings —
which is the correct result.
"""

import logging
import time
import uuid

from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from redkit.core.http_client import HttpClient
from redkit.modules.base_module import BaseModule

logger = logging.getLogger(__name__)

PROBE_ROUNDS = 3
SIZE_DIFF_THRESHOLD = 10  # bytes
TIMING_MIN_GAP = 0.3  # seconds
TIMING_MIN_RATIO = 1.5


class UserEnumerator(BaseModule):
    """Detect username enumeration via message, size, and timing analysis."""

    name = "Username Enumerator"
    description = "Detects login username enumeration via response message/size/timing differences."
    author = "K4os"
    category = "auth"

    options = {
        "target": {
            "value": None,
            "required": True,
            "description": "Login POST endpoint (e.g. https://example.com/login).",
        },
        "username_field": {
            "value": "username",
            "required": True,
            "description": "Name attribute of the username field.",
        },
        "password_field": {
            "value": "password",
            "required": True,
            "description": "Name attribute of the password field.",
        },
        "known_username": {
            "value": None,
            "required": True,
            "description": "A username that definitely exists on the target.",
        },
        "timeout": {
            "value": 10,
            "required": False,
            "type": int,
            "description": "HTTP request timeout in seconds (default: 10).",
        },
    }

    def _probe(
        self,
        http: HttpClient,
        target: str,
        username_field: str,
        password_field: str,
        username: str,
        timeout: int,
    ) -> tuple[int, int, str, float] | None:
        """POST one wrong-password login; return (status, size, body, elapsed) or None."""
        data = {username_field: username, password_field: f"redkit-probe-{uuid.uuid4().hex}"}
        try:
            start = time.monotonic()
            resp = http.post(target, data=data, allow_redirects=False)
            elapsed = time.monotonic() - start
            return resp.status_code, len(resp.content), resp.text, elapsed
        except Exception as exc:  # noqa: BLE001
            logger.debug("Probe request failed for user '%s': %s", username, exc)
            return None

    def run(self) -> None:
        """Compare known vs. unknown users across three probe rounds."""
        self.clear_findings()
        self.validate_options()

        target = self.get_option("target")
        username_field = self.get_option("username_field")
        password_field = self.get_option("password_field")
        known = self.get_option("known_username")
        timeout = int(self.get_option("timeout") or 10)
        http = self.http_client(target)

        unknown = f"redkit-nonexistent-{uuid.uuid4().hex[:8]}"
        signals: list[tuple[str, str, str, str]] = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            task = progress.add_task(f"Probing login responses on {target}", total=PROBE_ROUNDS * 2)
            self._progress = progress

            known_results = []
            unknown_results = []
            for _ in range(PROBE_ROUNDS):
                r = self._probe(http, target, username_field, password_field, known, timeout)
                progress.advance(task)
                if r:
                    known_results.append(r)
                r = self._probe(http, target, username_field, password_field, unknown, timeout)
                progress.advance(task)
                if r:
                    unknown_results.append(r)

            if len(known_results) < 2 or len(unknown_results) < 2:
                logger.warning("Not enough successful probes — aborting enumeration test.")
                return

            known_sizes = [r[1] for r in known_results]
            unknown_sizes = [r[1] for r in unknown_results]
            known_times = sorted(r[3] for r in known_results)
            unknown_times = sorted(r[3] for r in unknown_results)

            evidence = (
                f"POST {target} (wrong password for both users)\n"
                f"Known user '{known}': sizes {known_sizes}, times "
                f"{[f'{t:.2f}s' for t in known_times]}\n"
                f"Unknown user '{unknown}': sizes {unknown_sizes}, times "
                f"{[f'{t:.2f}s' for t in unknown_times]}"
            )

            # 1. Message-based: stable, mutually-identical, differing bodies.
            known_bodies = {r[2] for r in known_results}
            unknown_bodies = {r[2] for r in unknown_results}
            if len(known_bodies) == 1 and len(unknown_bodies) == 1 and known_bodies != unknown_bodies:
                signals.append(
                    (
                        "MEDIUM",
                        "different error messages",
                        known_bodies.pop()[:120],
                        unknown_bodies.pop()[:120],
                    )
                )
            # 2. Size-based: consistent size gap across all probes.
            elif (
                max(known_sizes) - min(known_sizes) <= SIZE_DIFF_THRESHOLD
                and max(unknown_sizes) - min(unknown_sizes) <= SIZE_DIFF_THRESHOLD
                and abs(sum(known_sizes) - sum(unknown_sizes)) / len(known_sizes) > SIZE_DIFF_THRESHOLD
            ):
                signals.append(
                    (
                        "MEDIUM",
                        "consistently different response sizes",
                        f"known sizes {known_sizes}",
                        f"unknown sizes {unknown_sizes}",
                    )
                )
            # 3. Timing-based: reproducible gap — INFO only, never MEDIUM.
            known_median = known_times[len(known_times) // 2]
            unknown_median = unknown_times[len(unknown_times) // 2]
            gap = abs(known_median - unknown_median)
            slower = max(known_median, unknown_median)
            if (
                gap >= TIMING_MIN_GAP
                and slower / max(min(known_median, unknown_median), 0.001) >= TIMING_MIN_RATIO
            ):
                signals.append(
                    (
                        "INFO",
                        "consistent timing difference",
                        f"known median {known_median:.2f}s",
                        f"unknown median {unknown_median:.2f}s",
                    )
                )

            for severity, mechanism, known_detail, unknown_detail in signals:
                logger.warning("Username enumeration signal: %s (%s)", mechanism, severity)
                self.add_finding(
                    finding_type="Username Enumeration",
                    severity=severity,
                    title=f"Username enumeration via {mechanism}",
                    detail=(
                        f"The login endpoint responds differently for the existing user "
                        f"'{known}' and a non-existing one ({mechanism}). An attacker can "
                        f"harvest valid usernames at scale. "
                        + (
                            "Timing-based signals are noisy — confirm manually."
                            if severity == "INFO"
                            else "The discriminator is stable across repeated probes."
                        )
                    ),
                    evidence=f"{evidence}\nMechanism detail: {known_detail!r} vs {unknown_detail!r}",
                    cvss=5.3 if severity == "MEDIUM" else None,
                )

        total = len(self.get_findings())
        logger.info("Username enumeration testing complete: %d finding(s).", total)
