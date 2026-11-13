"""
modules/auth/default_creds.py — Default credential checker.

Tries a built-in list of 20+ common default credential pairs against a
target login form and reports any successful logins as CRITICAL findings.

Success detection compares each response against a known-failed baseline
response captured before testing (plus the configured failure string), so
servers that omit the failure string or return redirect flows are handled
correctly. Credentials are never written to the log file in plaintext.
"""

import logging
import time
import uuid

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

_REDIRECT_STATUSES = (301, 302, 303, 307, 308)

# -----------------------------------------------------------------------
# 25 default credential pairs (username, password)
# -----------------------------------------------------------------------
DEFAULT_CREDS: list[tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "password123"),
    ("admin", "admin123"),
    ("admin", "1234"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", ""),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("root", ""),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("administrator", "admin"),
    ("user", "user"),
    ("user", "password"),
    ("guest", "guest"),
    ("guest", ""),
    ("test", "test"),
    ("demo", "demo"),
    ("support", "support"),
    ("info", "info"),
    ("webmaster", "webmaster"),
    ("superadmin", "superadmin"),
    ("manager", "manager"),
    ("operator", "operator"),
    ("service", "service"),
]


class DefaultCreds(BaseModule):
    """Check whether a login form accepts common default credentials.

    Iterates over a built-in list of common default username/password pairs,
    posting each to the target and comparing the response against both the
    configured failure string and a captured failed-login baseline.
    """

    name = "Default Credentials Checker"
    description = "Tries common default credential pairs against a login form."
    author = "K4os"
    category = "auth"

    options = {
        "target": {
            "value": None,
            "required": True,
            "description": "Full URL of the login form POST endpoint.",
        },
        "username_field": {
            "value": "username",
            "required": True,
            "description": "Name attribute of the username HTML field.",
        },
        "password_field": {
            "value": "password",
            "required": True,
            "description": "Name attribute of the password HTML field.",
        },
        "failure_string": {
            "value": None,
            "required": True,
            "description": "String present in the response body on failed login "
            "(e.g. 'Invalid credentials').",
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

    def _try_pair(
        self,
        http,
        target: str,
        username_field: str,
        password_field: str,
        username: str,
        password: str,
        failure_string: str,
        baseline_body: str | None,
    ) -> tuple[str, str] | None:
        """Attempt a single credential pair against the login form.

        Args:
            http: HTTP client.
            target: Login form POST URL.
            username_field: HTML field name for the username.
            password_field: HTML field name for the password.
            username: Username to try.
            password: Password to try.
            failure_string: Response string indicating failure.
            baseline_body: Body of a known-failed login attempt, or None if
                the baseline could not be captured.

        Returns:
            (username, password) tuple if login succeeded, else None.
        """
        data = {username_field: username, password_field: password}
        try:
            resp = http.post(target, data=data, allow_redirects=False)
            # A redirect after POST is the classic successful-login flow.
            if resp.status_code in _REDIRECT_STATUSES:
                return username, password
            # Non-2xx responses (401/403/429/5xx) are never a successful login.
            if not (200 <= resp.status_code < 300):
                return None
            if baseline_body is not None:
                if failure_string not in resp.text and resp.text != baseline_body:
                    return username, password
            else:
                if failure_string not in resp.text:
                    return username, password
        except Exception as exc:  # noqa: BLE001 — single-attempt failures are logged and skipped
            logger.debug("Request error for pair with user '%s': %s", username, exc)

        return None

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Iterate over DEFAULT_CREDS and test each pair sequentially."""
        self.clear_findings()
        self.validate_options()

        target = self.get_option("target")
        username_field = self.get_option("username_field")
        password_field = self.get_option("password_field")
        failure_string = self.get_option("failure_string")

        http = self.http_client(target)

        # ------------------------------------------------------------------
        # Baseline calibration — one deliberately-wrong login attempt whose
        # response becomes the reference "known failure" signature.
        # ------------------------------------------------------------------
        baseline_body: str | None = None
        try:
            baseline_resp = http.post(
                target,
                data={
                    username_field: f"redkit-baseline-{uuid.uuid4().hex[:8]}",
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

        logger.info("Default creds check: target=%s, pairs=%d", target, len(DEFAULT_CREDS))

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            task = progress.add_task(f"Testing default credentials on {target}", total=len(DEFAULT_CREDS))

            for username, password in DEFAULT_CREDS:
                progress.advance(task)
                result = self._try_pair(
                    http,
                    target,
                    username_field,
                    password_field,
                    username,
                    password,
                    failure_string,
                    baseline_body,
                )
                if result:
                    found_user, found_pass = result
                    # Never log plaintext credentials — they are recorded in
                    # the findings (and therefore the reports) only.
                    logger.warning(
                        "Default credentials accepted for user '%s' — password "
                        "withheld from logs (see findings/report).",
                        found_user,
                    )
                    self.add_finding(
                        finding_type="Default Credentials",
                        severity="CRITICAL",
                        title=f"Default credentials accepted: {found_user}:{found_pass}",
                        detail=(
                            f"The login endpoint at {target} accepted the default credential pair "
                            f"'{found_user}:{found_pass}'. This is a critical misconfiguration that "
                            f"grants immediate unauthorised access."
                        ),
                        evidence=(
                            f"POST {target}\n"
                            f"{username_field}={found_user}&{password_field}={found_pass}\n"
                            f"Response differed from the failed-login baseline and the "
                            f"failure string '{failure_string}' was absent."
                        ),
                    )
                # Small delay between requests
                time.sleep(0.3)

        total = len(self.get_findings())
        logger.info("Default creds check complete: %d valid pair(s) found.", total)
