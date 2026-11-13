"""
modules/recon/subdomain_takeover.py — Subdomain takeover checker.

For the target host (and optionally a wordlist of subdomains), resolves the
CNAME chain and fetches the host. A finding is confirmed **only when BOTH**
are true: a CNAME points at a third-party service AND the HTTP body matches
that vendor's well-known dangling fingerprint (e.g. S3 ``NoSuchBucket``,
GitHub Pages, Heroku ``No such app``).

Requiring both signals keeps false positives out: vendor-styled error pages
on properly configured hosts don't fire, and hosts without CNAMEs don't
either. Unresolvable hosts that still have a CNAME are reported as dangling
(takeover-eligible) on their own.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

import dns.exception
import dns.resolver
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from redkit.core.resources import default_wordlist
from redkit.modules.base_module import BaseModule

logger = logging.getLogger(__name__)

_OPTIONAL_WORDLIST = default_wordlist("subdomains.txt")

#: fingerprint (lowercase substring) → vendor. Only high-confidence,
#: vendor-specific strings — generic "404 not found" texts must never match.
TAKEOVER_FINGERPRINTS: dict[str, str] = {
    "nosuchbucket": "AWS S3",
    "the specified bucket does not exist": "AWS S3",
    "there isn't a github pages site here": "GitHub Pages",
    "there's nothing here, yet.": "Heroku",
    "no such app": "Heroku",
    "404 web site not found": "Azure",
    "fastly error: unknown domain": "Fastly",
    "sorry, this shop is currently unavailable": "Shopify",
    "repository not found": "Bitbucket",
    "project not found": "Surge.sh",
}

#: fingerprints only trusted when the CNAME host maps to the same vendor.
CNAME_VENDOR_HINTS: dict[str, list[str]] = {
    "AWS S3": ["s3", "s3-website", "s3.amazonaws.com"],
    "GitHub Pages": ["github.io"],
    "Heroku": ["herokuapp.com", "herokudns.com"],
    "Azure": ["azurewebsites.net", "cloudapp.azure.com", "trafficmanager.net"],
    "Fastly": ["fastly.net", "fastlylb.net"],
    "Shopify": ["myshopify.com"],
    "Bitbucket": ["bitbucket.io"],
    "Surge.sh": ["surge.sh"],
}


class SubdomainTakeover(BaseModule):
    """Check hosts for dangling CNAMEs paired with vendor takeover fingerprints."""

    name = "Subdomain Takeover Checker"
    description = "Detects dangling CNAMEs with vendor takeover fingerprints (signature-confirmed)."
    author = "K4os"
    category = "recon"

    options = {
        "target": {
            "value": None,
            "required": True,
            "description": "Target domain or URL (e.g. https://example.com).",
        },
        "subdomain_wordlist": {
            "value": "",
            "required": False,
            "type": str,
            "description": "Optional wordlist of subdomains to check in addition to the target host.",
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

    # ------------------------------------------------------------------
    # DNS helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_cname(resolver: dns.resolver.Resolver, host: str) -> str | None:
        """Return the first CNAME target for *host*, or None."""
        try:
            answers = resolver.resolve(host, "CNAME")
            for rdata in answers:
                return str(rdata.target).rstrip(".").lower()
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout,
            dns.exception.Timeout,
        ):
            return None
        except Exception as exc:  # noqa: BLE001
            logger.debug("CNAME resolution error for %s: %s", host, exc)
            return None
        return None

    @staticmethod
    def _resolves(resolver: dns.resolver.Resolver, host: str) -> bool:
        """Return True when *host* has any A/AAAA record."""
        for rtype in ("A", "AAAA"):
            try:
                resolver.resolve(host, rtype)
                return True
            except Exception:  # noqa: BLE001
                continue
        return False

    def _check_host(self, http, resolver: dns.resolver.Resolver, host: str) -> None:
        """Assess one host for takeover; records a finding when confirmed."""
        host = host.lower().strip().rstrip(".")
        if not host:
            return

        cname = self._resolve_cname(resolver, host)
        body = ""
        status = 0
        try:
            resp = http.get(f"https://{host}", allow_redirects=True)
            status, body = resp.status_code, resp.text
        except Exception as exc:  # noqa: BLE001 — fall back to DNS-only verdict
            logger.debug("HTTP fetch failed for %s: %s", host, exc)

        body_lower = body.lower()

        # Dangling: CNAME exists but the host no longer resolves at all.
        if cname and not self._resolves(resolver, host):
            logger.warning("Dangling CNAME: %s → %s (host unresolvable)", host, cname)
            self.add_finding(
                finding_type="Subdomain Takeover",
                severity="HIGH",
                title=f"Dangling CNAME: {host} → {cname}",
                detail=(
                    f"{host} has a CNAME to {cname} but does not resolve to any address. "
                    f"If the third-party resource can be re-claimed, the subdomain is "
                    f"takeover-eligible. Verify claimability manually."
                ),
                evidence=f"{host} CNAME → {cname} (NXDOMAIN on A/AAAA)",
                cvss=8.2,
            )
            return

        if not cname:
            return

        # Body fingerprint must match a known vendor signature…
        matched_vendor: str | None = None
        for fingerprint, vendor in TAKEOVER_FINGERPRINTS.items():
            if fingerprint and fingerprint in body_lower:
                matched_vendor = vendor or fingerprint
                break
        if not matched_vendor:
            return

        # …and (when the vendor has CNAME hints) the CNAME must belong to it.
        for vendor, hints in CNAME_VENDOR_HINTS.items():
            if matched_vendor.startswith(vendor) and not any(h in cname for h in hints):
                logger.debug(
                    "Fingerprint '%s' on %s ignored — CNAME %s does not belong to the vendor.",
                    matched_vendor,
                    host,
                    cname,
                )
                return

        logger.warning("Subdomain takeover signature: %s (CNAME %s, vendor %s)", host, cname, matched_vendor)
        self.add_finding(
            finding_type="Subdomain Takeover",
            severity="HIGH",
            title=f"Subdomain takeover signature: {host} ({matched_vendor})",
            detail=(
                f"{host} is a CNAME to {cname} ({matched_vendor}) and the HTTP response matches the "
                f"vendor's unclaimed-resource fingerprint. If the third-party resource can be "
                f"registered again, an attacker can serve content on your subdomain — including "
                f"cookies scoped to the parent domain."
            ),
            evidence=(
                f"{host} CNAME → {cname}\nHTTP {status} body matched vendor fingerprint\n"
                f"Response snippet: {body[:200]}"
            ),
            cvss=8.2,
        )

    def run(self) -> None:
        """Check the target host (and optional wordlist) for takeover."""
        self.clear_findings()
        self.validate_options()

        target = str(self.get_option("target"))
        host = urlparse(target if "://" in target else f"https://{target}").hostname or target
        threads = int(self.get_option("threads") or 5)
        timeout = float(self.get_option("timeout") or 10)

        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        http = self.http_client(f"https://{host}")

        hosts = [host]
        wordlist_path = str(self.get_option("subdomain_wordlist") or "").strip()
        if wordlist_path:
            wl = Path(wordlist_path)
            if wl.is_file():
                with open(wl, encoding="utf-8", errors="ignore") as fh:
                    hosts += [
                        f"{line.strip()}.{host}" for line in fh if line.strip() and not line.startswith("#")
                    ]

        logger.info("Subdomain takeover check: %d host(s), base=%s", len(hosts), host)

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            task = progress.add_task(f"Checking takeover on {host}", total=len(hosts))
            self._progress = progress

            with ThreadPoolExecutor(max_workers=threads) as executor:
                future_map = {executor.submit(self._check_host, http, resolver, h): h for h in hosts}
                for future in as_completed(future_map):
                    progress.advance(task)
                    try:
                        future.result()
                    except Exception as exc:  # noqa: BLE001
                        logger.debug("Takeover check error for %s: %s", future_map[future], exc)

        total = len(self.get_findings())
        logger.info("Subdomain takeover check complete: %d finding(s).", total)
