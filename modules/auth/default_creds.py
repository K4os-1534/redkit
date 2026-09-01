"""
modules/auth/default_creds.py — Default credential checker.

Tries a built-in list of 20+ common default credential pairs against a
target login form and reports any successful logins as CRITICAL findings.
"""

import logging
import time
from pathlib import Path
from typing import Optional

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
    posting each to the target and checking the response for the absence
    of a failure string to determine success.
    """

    name = "Default Credentials Checker"
    description = "Tries common default credential pairs against a login form."
    author = "RedKit"
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
            "description": "String present in the response body on failed login (e.g. 'Invalid credentials').",
        },
        "timeout": {
            "value": "5",
            "required": False,
            "description": "HTTP request timeout in seconds (default: 5).",
        },
    }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _try_pair(
        self,
        target: str,
        username_field: str,
        password_field: str,
        username: str,
        password: str,
        failure_string: str,
        timeout: int,
        headers: dict,
    ) -> Optional[tuple[str, str]]:
        """Attempt a single credential pair against the login form.

        Args:
            target: Login form POST URL.
            username_field: HTML field name for the username.
            password_field: HTML field name for the password.
            username: Username to try.
            password: Password to try.
            failure_string: Response string indicating failure.
            timeout: HTTP timeout in seconds.
            headers: HTTP headers dict.

        Returns:
            (username, password) tuple if login succeeded, else None.
        """
        data = {username_field: username, password_field: password}
        try:
            resp = requests.post(
                target,
                data=data,
                timeout=timeout,
                headers=headers,
                verify=False,
                allow_redirects=True,
            )
            if failure_string not in resp.text:
                return username, password
        except RequestException as exc:
            logger.debug("Request error for %s:%s — %s", username, password, exc)

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
        timeout = int(self.get_option("timeout") or 5)

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

        logger.info(
            "Default creds check: target=%s, pairs=%d", target, len(DEFAULT_CREDS)
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            task = progress.add_task(
                f"Testing default credentials on {target}", total=len(DEFAULT_CREDS)
            )

            for username, password in DEFAULT_CREDS:
                progress.advance(task)
                result = self._try_pair(
                    target, username_field, password_field,
                    username, password, failure_string, timeout, headers,
                )
                if result:
                    found_user, found_pass = result
                    logger.warning("Default creds hit: %s / %s", found_user, found_pass)
                    self._add_finding(
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
                            f"Failure string '{failure_string}' was absent from response."
                        ),
                    )
                # Small delay between requests
                time.sleep(0.3)

        total = len(self.get_findings())
        logger.info("Default creds check complete: %d valid pair(s) found.", total)
