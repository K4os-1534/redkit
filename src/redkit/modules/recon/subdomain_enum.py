"""
modules/recon/subdomain_enum.py — Subdomain enumeration via DNS A record resolution.

Resolves each entry in a wordlist as a subdomain of the target domain using
dnspython, concurrently via ThreadPoolExecutor, and reports discovered
subdomains with their resolved IP addresses.
"""

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

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

_DEFAULT_WORDLIST = default_wordlist("subdomains.txt")


class SubdomainEnum(BaseModule):
    """Enumerate subdomains via concurrent DNS A-record resolution.

    Reads a wordlist of subdomain prefixes, prepends each to the target
    domain, and attempts a DNS A-record lookup. Successfully resolved
    subdomains are recorded as INFO findings. A single resolver instance is
    shared across all worker threads.
    """

    name = "Subdomain Enumerator"
    description = "Resolves subdomains from a wordlist via DNS A-record lookup."
    author = "K4os"
    category = "recon"

    options = {
        "target": {
            "value": None,
            "required": True,
            "description": "Target base domain (e.g. example.com). Do not include http://.",
        },
        "wordlist": {
            "value": str(_DEFAULT_WORDLIST),
            "required": False,
            "type": str,
            "description": "Path to subdomain wordlist file.",
        },
        "threads": {
            "value": 10,
            "required": False,
            "type": int,
            "description": "Number of concurrent threads (default: 10).",
        },
        "timeout": {
            "value": 3,
            "required": False,
            "type": int,
            "description": "DNS query timeout in seconds (default: 3).",
        },
    }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _strip_scheme(target: str) -> str:
        """Remove http:// or https:// scheme from the target string.

        Args:
            target: Raw target string, possibly with scheme.

        Returns:
            Bare domain/hostname string.
        """
        return re.sub(r"^https?://", "", target).rstrip("/").split("/")[0]

    @staticmethod
    def _load_wordlist(path: str) -> list[str]:
        """Read a wordlist file into a list of stripped, non-empty lines.

        Args:
            path: Path to the wordlist file.

        Returns:
            List of subdomain prefix strings.
        """
        wl_path = Path(path)
        if not wl_path.is_file():
            logger.warning("Wordlist not found: %s", path)
            return []
        with open(wl_path, encoding="utf-8", errors="ignore") as fh:
            return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

    @staticmethod
    def _resolve(resolver: dns.resolver.Resolver, fqdn: str) -> list[str] | None:
        """Resolve a FQDN to a list of A-record IP addresses.

        Args:
            resolver: Shared dnspython resolver instance.
            fqdn: Fully-qualified domain name to resolve.

        Returns:
            List of IP address strings, or None if resolution failed.
        """
        try:
            answers = resolver.resolve(fqdn, "A")
            return [rdata.address for rdata in answers]
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout,
            dns.exception.Timeout,
        ):
            return None
        except Exception as exc:  # noqa: BLE001 — DNS has many failure modes
            logger.debug("Resolution error for %s: %s", fqdn, exc)
            return None

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Execute subdomain enumeration against the target domain.

        Reads the wordlist, spawns a thread pool, resolves each subdomain,
        and records discovered hosts as INFO findings.
        """
        self.clear_findings()
        self.validate_options()

        raw_target = str(self.get_option("target"))
        domain = self._strip_scheme(raw_target)
        wordlist_path = self.get_option("wordlist")
        threads = int(self.get_option("threads") or 10)
        timeout = float(self.get_option("timeout") or 3)

        words = self._load_wordlist(wordlist_path)
        if not words:
            logger.error("Empty wordlist — aborting subdomain enum.")
            return

        # One shared resolver — cheaper than constructing one per lookup.
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        logger.info("Starting subdomain enum: domain=%s, words=%d, threads=%d", domain, len(words), threads)

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            task = progress.add_task(f"Resolving subdomains of {domain}", total=len(words))
            self._progress = progress

            with ThreadPoolExecutor(max_workers=threads) as executor:
                future_map = {
                    executor.submit(self._resolve, resolver, f"{word}.{domain}"): word for word in words
                }

                for future in as_completed(future_map):
                    word = future_map[future]
                    fqdn = f"{word}.{domain}"
                    progress.advance(task)
                    try:
                        ips = future.result()
                        if ips:
                            ip_str = ", ".join(ips)
                            logger.debug("Discovered: %s → %s", fqdn, ip_str)
                            self.add_finding(
                                finding_type="Subdomain",
                                severity="INFO",
                                title=f"Subdomain discovered: {fqdn}",
                                detail=f"DNS A-record resolved to: {ip_str}",
                                evidence=f"{fqdn} → {ip_str}",
                            )
                    except Exception as exc:  # noqa: BLE001
                        logger.debug("Error resolving %s: %s", fqdn, exc)

        total = len(self.get_findings())
        logger.info("Subdomain enum complete: %d subdomain(s) found.", total)
