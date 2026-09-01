"""
modules/recon/tech_fingerprint.py — Technology fingerprinting module.

Makes a single HTTP request to the target and analyses response headers
and HTML body for signatures of server-side and client-side technologies.
No wordlist required — entirely pattern-based detection.
"""

import logging
import re
from pathlib import Path

import requests
from requests.exceptions import RequestException
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from modules.base_module import BaseModule

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# -----------------------------------------------------------------------
# Detection patterns
# -----------------------------------------------------------------------

# Header-based detections: (header_name, regex_pattern, tech_name)
HEADER_PATTERNS: list[tuple[str, str, str]] = [
    ("server", r"Apache", "Apache HTTP Server"),
    ("server", r"nginx", "Nginx"),
    ("server", r"Microsoft-IIS", "Microsoft IIS"),
    ("server", r"LiteSpeed", "LiteSpeed Web Server"),
    ("server", r"Caddy", "Caddy"),
    ("server", r"Tomcat", "Apache Tomcat"),
    ("server", r"Jetty", "Eclipse Jetty"),
    ("x-powered-by", r"PHP/([\d.]+)", "PHP"),
    ("x-powered-by", r"ASP\.NET", "ASP.NET"),
    ("x-powered-by", r"Express", "Express.js"),
    ("x-powered-by", r"Servlet", "Java Servlet"),
    ("x-generator", r"Drupal", "Drupal CMS"),
    ("x-generator", r"WordPress", "WordPress CMS"),
    ("x-drupal-cache", r".*", "Drupal CMS"),
    ("x-wp-total", r".*", "WordPress REST API"),
    ("x-shopify-stage", r".*", "Shopify"),
    ("via", r"Varnish", "Varnish Cache"),
    ("x-varnish", r".*", "Varnish Cache"),
    ("cf-ray", r".*", "Cloudflare CDN"),
    ("x-amz-cf-id", r".*", "Amazon CloudFront"),
    ("x-cache", r".*", "Caching Layer"),
]

# Cookie-name-based detections: (cookie_name_regex, tech_name)
COOKIE_PATTERNS: list[tuple[str, str]] = [
    (r"PHPSESSID", "PHP Session"),
    (r"JSESSIONID", "Java EE / Servlet"),
    (r"ASP\.NET_SessionId", "ASP.NET"),
    (r"wordpress_logged_in|wp-settings", "WordPress"),
    (r"laravel_session", "Laravel Framework"),
    (r"XSRF-TOKEN", "Laravel / CSRF Protection"),
    (r"ci_session", "CodeIgniter Framework"),
    (r"_session_id", "Ruby on Rails"),
    (r"connect\.sid", "Node.js / Express Session"),
    (r"csrftoken", "Django CSRF"),
    (r"sessionid", "Django Session"),
]

# HTML body patterns: (regex_pattern, tech_name)
BODY_PATTERNS: list[tuple[str, str]] = [
    (r"<meta[^>]+generator[^>]+WordPress", "WordPress CMS"),
    (r"<meta[^>]+generator[^>]+Drupal", "Drupal CMS"),
    (r"<meta[^>]+generator[^>]+Joomla", "Joomla CMS"),
    (r"<meta[^>]+generator[^>]+Wix", "Wix Website Builder"),
    (r"wp-content/", "WordPress CMS"),
    (r"wp-includes/", "WordPress CMS"),
    (r"/sites/default/files/", "Drupal CMS"),
    (r'Drupal\.settings', "Drupal CMS"),
    (r"jquery[.-][\d.]+\.min\.js", "jQuery"),
    (r"react\.development\.js|react\.production\.min\.js|__REACT_DEVTOOLS", "React"),
    (r"vue\.js|vue\.min\.js|Vue\.component\(", "Vue.js"),
    (r"angular\.js|angular\.min\.js|ng-app=", "AngularJS"),
    (r"angular/core|@angular", "Angular"),
    (r"bootstrap\.min\.js|bootstrap\.bundle", "Bootstrap"),
    (r"laravel|csrf-token.*Laravel", "Laravel Framework"),
    (r"__NEXT_DATA__", "Next.js"),
    (r"__nuxt", "Nuxt.js"),
    (r"gatsby-root|gatsby-focus-wrapper", "Gatsby"),
    (r"svelte-", "Svelte"),
    (r'Powered by <a[^>]+>vBulletin', "vBulletin"),
    (r"<meta[^>]+generator[^>]+Magento", "Magento"),
    (r"Mage\.Cookies", "Magento"),
    (r"typo3", "TYPO3 CMS"),
]


class TechFingerprint(BaseModule):
    """Fingerprint web technologies from HTTP response headers and HTML body.

    A single HTTP request is sufficient — no wordlist or brute-forcing.
    All detections are returned as INFO-severity findings.
    """

    name = "Technology Fingerprinter"
    description = "Identifies server/client-side tech from headers and HTML body."
    author = "RedKit"
    category = "recon"

    options = {
        "target": {
            "value": None,
            "required": True,
            "description": "Target URL to fingerprint (e.g. https://example.com).",
        },
        "timeout": {
            "value": "10",
            "required": False,
            "description": "HTTP request timeout in seconds (default: 10).",
        },
    }

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Fetch the target and run all fingerprinting checks."""
        self.clear_findings()
        self.validate_options()

        target = self.get_option("target")
        timeout = int(self.get_option("timeout") or 10)

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

        logger.info("Tech fingerprinting: %s", target)

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            task = progress.add_task(f"Fingerprinting {target}", total=None)

            try:
                resp = requests.get(
                    target,
                    timeout=timeout,
                    headers={"User-Agent": user_agent},
                    verify=False,
                    allow_redirects=True,
                )
            except RequestException as exc:
                logger.error("Request failed for %s: %s", target, exc)
                return

            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.text
            cookies = resp.cookies
            detected: set[str] = set()

            # --- Header analysis ---
            for header_name, pattern, tech in HEADER_PATTERNS:
                value = headers.get(header_name, "")
                if value and re.search(pattern, value, re.IGNORECASE):
                    if tech not in detected:
                        detected.add(tech)
                        evidence = f"Header: {header_name}: {value}"
                        self._add_finding(
                            finding_type="Technology",
                            severity="INFO",
                            title=f"Technology detected: {tech}",
                            detail=f"Identified via HTTP response header '{header_name}'.",
                            evidence=evidence,
                        )

            # --- Cookie name analysis ---
            for cookie_name_re, tech in COOKIE_PATTERNS:
                for cookie in cookies:
                    if re.search(cookie_name_re, cookie.name, re.IGNORECASE):
                        if tech not in detected:
                            detected.add(tech)
                            self._add_finding(
                                finding_type="Technology",
                                severity="INFO",
                                title=f"Technology detected: {tech}",
                                detail=f"Identified via Set-Cookie name '{cookie.name}'.",
                                evidence=f"Set-Cookie: {cookie.name}={cookie.value[:40]}",
                            )

            # --- HTML body analysis ---
            for pattern, tech in BODY_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    if tech not in detected:
                        detected.add(tech)
                        match_obj = re.search(pattern, body, re.IGNORECASE)
                        snippet = (match_obj.group(0)[:100] if match_obj else "")
                        self._add_finding(
                            finding_type="Technology",
                            severity="INFO",
                            title=f"Technology detected: {tech}",
                            detail="Identified via HTML body pattern match.",
                            evidence=f"Pattern match: …{snippet}…",
                        )

            # --- Content-Type ---
            content_type = headers.get("content-type", "")
            if content_type:
                self._add_finding(
                    finding_type="Technology",
                    severity="INFO",
                    title=f"Content-Type: {content_type}",
                    detail="HTTP Content-Type header value.",
                    evidence=f"Content-Type: {content_type}",
                )

            progress.update(task, completed=True)

        logger.info("Fingerprinting complete: %d technologies detected.", len(detected))

