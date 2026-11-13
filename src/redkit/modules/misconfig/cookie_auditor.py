"""
modules/misconfig/cookie_auditor.py — Cookie security attribute auditor.

Parses the raw ``Set-Cookie`` response headers (attributes preserved, unlike
the parsed cookie jar) and reports missing ``Secure``, ``HttpOnly``, and
``SameSite`` attributes.

To keep noise down, missing ``Secure``/``HttpOnly`` is rated MEDIUM only for
session-like cookie names (session, sid, token, auth, jwt, …); everything
else is LOW. Cookie names and attributes are facts — no heuristics beyond
that name classification.
"""

import logging
import re
from http.cookies import SimpleCookie

from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from redkit.modules.base_module import BaseModule

logger = logging.getLogger(__name__)

#: Cookie names matching this pattern are treated as session-bearing.
SESSION_LIKE = re.compile(r"session|sid|token|auth|login|jwt|remember|api_key|api-key", re.IGNORECASE)


class CookieAuditor(BaseModule):
    """Audit Set-Cookie headers for missing security attributes."""

    name = "Cookie Auditor"
    description = "Audits Set-Cookie headers for missing Secure/HttpOnly/SameSite attributes."
    author = "K4os"
    category = "misconfig"

    options = {
        "target": {
            "value": None,
            "required": True,
            "description": "Target URL whose response cookies are audited.",
        },
        "timeout": {
            "value": 10,
            "required": False,
            "type": int,
            "description": "HTTP request timeout in seconds (default: 10).",
        },
    }

    def run(self) -> None:
        """Fetch the target and audit every Set-Cookie header."""
        self.clear_findings()
        self.validate_options()

        target = self.get_option("target")
        http = self.http_client(target)

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            task = progress.add_task(f"Auditing cookies on {target}", total=None)
            self._progress = progress

            try:
                resp = http.get(target)
            except Exception as exc:  # noqa: BLE001 — network failures end the audit
                logger.error("Request failed for %s: %s", target, exc)
                return

            # raw.headers preserves duplicate Set-Cookie headers.
            raw_headers = getattr(resp, "raw", None)
            set_cookies = (
                raw_headers.headers.getlist("Set-Cookie")
                if raw_headers is not None
                else [v for k, v in resp.headers.items() if k.lower() == "set-cookie"]
            )
            scheme = target.split("://", 1)[0].lower()

            seen: set[str] = set()
            for raw in set_cookies:
                cookie = SimpleCookie()
                try:
                    cookie.load(raw)
                except Exception:  # noqa: BLE001 — skip unparsable cookies
                    continue
                for name in cookie:
                    if name in seen:
                        continue
                    seen.add(name)
                    lowered = raw.lower()
                    session_like = bool(SESSION_LIKE.search(name))

                    missing = []
                    if scheme == "https" and not self._has_flag(raw, "secure"):
                        missing.append("Secure")
                    if not self._has_flag(raw, "httponly"):
                        missing.append("HttpOnly")
                    if "samesite=" not in lowered:
                        missing.append("SameSite")

                    if not missing:
                        continue

                    if "Secure" in missing and "HttpOnly" in missing and session_like:
                        severity = "MEDIUM"
                    elif session_like:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"

                    self.add_finding(
                        finding_type="Cookie Security",
                        severity=severity,
                        title=f"Cookie '{name}' missing: {', '.join(missing)}",
                        detail=(
                            f"The '{name}' cookie ({'session-like' if session_like else 'non-session'}) "
                            f"was set without: {', '.join(missing)}. "
                            + (
                                "Without Secure the cookie travels over plain HTTP; "
                                if "Secure" in missing
                                else ""
                            )
                            + (
                                "without HttpOnly scripts can read it (XSS escalation); "
                                if "HttpOnly" in missing
                                else ""
                            )
                            + (
                                "without SameSite it may be sent on cross-site requests (CSRF)."
                                if "SameSite" in missing
                                else ""
                            )
                        ),
                        evidence=f"Set-Cookie: {raw[:200]}",
                    )

            progress.update(task, completed=True)

        total = len(self.get_findings())
        logger.info("Cookie audit complete: %d finding(s).", total)

    @staticmethod
    def _has_flag(raw: str, flag: str) -> bool:
        """Return True when *raw* contains *flag* as a cookie attribute."""
        return bool(re.search(rf"(?:^|;)\s*{flag}\s*(?:;|$)", raw, re.IGNORECASE))
