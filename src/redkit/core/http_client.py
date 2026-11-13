"""
core/http_client.py — Shared HTTP client for all RedKit modules.

Every module issues its requests through this client so that global
configuration (user agent, TLS verification, proxy, rate limit, retries)
and the scope guard apply uniformly.

Security-relevant behaviour:

- TLS certificate verification is ON by default; disabling it requires an
  explicit ``verify_ssl: false`` in config.yaml (or per-request override).
- A scope (allowed host) can be attached; requests and redirect hops to
  other hosts raise :class:`OutOfScopeError`. This prevents payloads from
  leaking to out-of-scope systems via redirects.
- Environment proxies (HTTP_PROXY etc.) are ignored; only the explicitly
  configured ``proxy`` setting is used.
"""

import logging
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import requests
import urllib3

logger = logging.getLogger(__name__)

#: Status codes treated as redirects by the manual redirect follower.
REDIRECT_STATUSES = (301, 302, 303, 307, 308)


class OutOfScopeError(RuntimeError):
    """Raised when a request or redirect targets a host outside the scope."""


@dataclass
class HttpClientConfig:
    """Configuration for :class:`HttpClient`, built from RedKit config keys."""

    user_agent: str = "RedKit (Authorized Security Testing)"
    timeout: float = 10.0
    verify_ssl: bool = True
    proxy: str | None = None
    rate_limit: float = 0.0  # minimum seconds between requests per host
    max_retries: int = 0  # retries on connection-level errors
    retry_backoff: float = 0.5  # base seconds for exponential backoff
    max_redirects: int = 10
    extra_headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)


class HttpClient:
    """Thread-safe HTTP client wrapping :class:`requests.Session`.

    Usage::

        client = HttpClient(HttpClientConfig(user_agent="RedKit/2.0"),
                            scope="example.com")
        resp = client.get("https://example.com/page")
    """

    def __init__(self, config: HttpClientConfig, scope: str | None = None) -> None:
        """Initialise the client.

        Args:
            config: Client configuration (usually derived from config.yaml).
            scope: Optional allowed host; the exact host and any subdomain of
                it are permitted. None disables scope enforcement.
        """
        self.config = config
        self.scope = scope.lower() if scope else None
        self._session = requests.Session()
        self._session.trust_env = False  # ignore HTTP_PROXY etc. — proxy is explicit
        self._session.headers["User-Agent"] = config.user_agent
        if config.extra_headers:
            self._session.headers.update(config.extra_headers)
        if config.cookies:
            self._session.cookies.update(config.cookies)
        if config.proxy:
            self._session.proxies = {"http": config.proxy, "https": config.proxy}

        if not config.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.warning("TLS certificate verification is DISABLED (verify_ssl: false).")

        self._rate_locks: dict[str, threading.Lock] = {}
        self._last_request: dict[str, float] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, url: str, **kwargs: object) -> requests.Response:
        """GET *url* (see :meth:`request` for keyword arguments).

        Args:
            url: Absolute URL.
            **kwargs: Forwarded to :meth:`request`.

        Returns:
            The response.
        """
        return self.request("GET", url, **kwargs)  # type: ignore[arg-type]

    def post(self, url: str, *, data: dict | str | None = None, **kwargs: object) -> requests.Response:
        """POST to *url* (see :meth:`request` for keyword arguments).

        Args:
            url: Absolute URL.
            data: Form/body payload.
            **kwargs: Forwarded to :meth:`request`.

        Returns:
            The response.
        """
        return self.request("POST", url, data=data, **kwargs)  # type: ignore[arg-type]

    def request(
        self,
        method: str,
        url: str,
        *,
        data: dict | str | None = None,
        params: dict | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        verify: bool | None = None,
        allow_redirects: bool = True,
    ) -> requests.Response:
        """Send an HTTP request with scope checks, rate limiting, and retries.

        Redirects are followed manually (when *allow_redirects* is true) so
        that every hop is scope-checked.

        Args:
            method: HTTP method (GET, POST, …).
            url: Absolute URL.
            data: Form/body payload.
            params: Query parameters.
            headers: Per-request headers merged over the session headers.
            timeout: Per-request timeout override (seconds).
            verify: Per-request TLS verification override.
            allow_redirects: Follow redirects (scope-checked per hop).

        Returns:
            The final :class:`requests.Response`.

        Raises:
            OutOfScopeError: The URL or a redirect hop is out of scope.
            requests.exceptions.TooManyRedirects: More than the configured
                maximum redirects were followed.
            requests.exceptions.RequestException: The request failed after
                any configured retries.
        """
        method = method.upper()
        current_url = url
        current_method = method
        current_data = data
        redirects_left = self.config.max_redirects

        self._check_scope(current_url)

        while True:
            resp = self._send_with_retry(
                current_method,
                current_url,
                data=current_data,
                params=params,
                headers=headers,
                timeout=timeout,
                verify=verify,
            )
            if not allow_redirects or resp.status_code not in REDIRECT_STATUSES:
                return resp

            location = resp.headers.get("Location")
            if not location:
                return resp
            if redirects_left <= 0:
                raise requests.exceptions.TooManyRedirects(
                    f"Exceeded {self.config.max_redirects} redirects: {url}"
                )
            redirects_left -= 1

            next_url = urljoin(current_url, location)
            self._check_scope(next_url)
            logger.debug("Following redirect: %s -> %s", current_url, next_url)

            # Browsers switch POST→GET on 301/302/303; 307/308 keep the method.
            if current_method == "POST" and resp.status_code in (301, 302, 303):
                current_method = "GET"
                current_data = None
            current_url = next_url

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _check_scope(self, url: str) -> None:
        """Raise OutOfScopeError when *url*'s host is outside the scope.

        Args:
            url: URL to validate.

        Raises:
            OutOfScopeError: The host is neither the scope host nor a
                subdomain of it.
        """
        if self.scope is None:
            return
        host = urlparse(url).hostname
        if host is None:
            raise OutOfScopeError(f"URL has no hostname: {url}")
        host = host.lower()
        if host != self.scope and not host.endswith("." + self.scope):
            raise OutOfScopeError(f"Refusing request to out-of-scope host '{host}' (scope: '{self.scope}')")

    def _throttle(self, url: str) -> None:
        """Sleep so that per-host requests respect the configured rate limit.

        Args:
            url: URL about to be requested (its host is the throttle key).
        """
        if self.config.rate_limit <= 0:
            return
        key = urlparse(url).netloc.lower()
        lock = self._rate_locks.setdefault(key, threading.Lock())
        with lock:
            last = self._last_request.get(key)
            if last is not None:
                wait = self.config.rate_limit - (time.monotonic() - last)
                if wait > 0:
                    time.sleep(wait)
            self._last_request[key] = time.monotonic()

    def _send_with_retry(
        self,
        method: str,
        url: str,
        *,
        data: dict | str | None,
        params: dict | None,
        headers: dict[str, str] | None,
        timeout: float | None,
        verify: bool | None,
    ) -> requests.Response:
        """Send one request, retrying connection-level failures.

        Args:
            method: HTTP method.
            url: Absolute URL.
            data: Body payload.
            params: Query parameters.
            headers: Per-request headers.
            timeout: Timeout override (None → configured default).
            verify: TLS verification override (None → configured default).

        Returns:
            The :class:`requests.Response` (redirects NOT followed).

        Raises:
            requests.exceptions.RequestException: After exhausting retries.
        """
        resolved_timeout = self.config.timeout if timeout is None else timeout
        resolved_verify = self.config.verify_ssl if verify is None else verify

        attempt = 0
        while True:
            self._throttle(url)
            try:
                return self._send_raw(
                    method,
                    url,
                    data=data,
                    params=params,
                    headers=headers,
                    timeout=resolved_timeout,
                    verify=resolved_verify,
                )
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
                attempt += 1
                if attempt > self.config.max_retries:
                    raise
                backoff = self.config.retry_backoff * (2 ** (attempt - 1))
                logger.warning(
                    "Request to %s failed (%s) — retry %d/%d in %.1fs",
                    url,
                    exc.__class__.__name__,
                    attempt,
                    self.config.max_retries,
                    backoff,
                )
                time.sleep(backoff)

    def _send_raw(
        self,
        method: str,
        url: str,
        *,
        data: dict | str | None,
        params: dict | None,
        headers: dict[str, str] | None,
        timeout: float,
        verify: bool,
    ) -> requests.Response:
        """Perform the underlying session request (seam for tests).

        Args:
            method: HTTP method.
            url: Absolute URL.
            data: Body payload.
            params: Query parameters.
            headers: Per-request headers.
            timeout: Resolved timeout in seconds.
            verify: Resolved TLS verification flag.

        Returns:
            The :class:`requests.Response` (redirects NOT followed).
        """
        return self._session.request(
            method,
            url,
            data=data,
            params=params,
            headers=headers,
            timeout=timeout,
            verify=verify,
            allow_redirects=False,
        )
