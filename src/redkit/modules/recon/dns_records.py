"""
modules/recon/dns_records.py — DNS record auditor.

Resolves A, AAAA, CNAME, MX, NS, and TXT records for the target host and
reports them as INFO findings. Email-spoofing checks (missing SPF/DMARC)
only fire when the host actually has MX records — auditing a web hostname
without mail never produces misleading findings.

An optional AXFR (zone transfer) attempt against the authoritative
nameservers is disabled by default: it is an intrusive probe and must be
explicitly enabled via the ``attempt_axfr`` option.
"""

import logging
from urllib.parse import urlparse

import dns.exception
import dns.query
import dns.resolver
import dns.zone
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from redkit.modules.base_module import BaseModule

logger = logging.getLogger(__name__)

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]


class DnsRecordsAuditor(BaseModule):
    """Enumerate DNS records and audit SPF/DMARC when the host handles mail."""

    name = "DNS Records Auditor"
    description = "Enumerates DNS records; checks SPF/DMARC for mail domains; optional AXFR."
    author = "K4os"
    category = "recon"

    options = {
        "target": {
            "value": None,
            "required": True,
            "description": "Target domain or URL (e.g. example.com).",
        },
        "timeout": {
            "value": 5,
            "required": False,
            "type": int,
            "description": "DNS query timeout in seconds (default: 5).",
        },
        "attempt_axfr": {
            "value": False,
            "required": False,
            "type": bool,
            "description": "Attempt a zone transfer (AXFR) against the authoritative nameservers. "
            "Intrusive — enable only on domains you are authorized to test.",
        },
    }

    @staticmethod
    def _strip_to_host(target: str) -> str:
        """Normalise a target (domain or URL) to a bare hostname."""
        host = urlparse(target if "://" in target else f"https://{target}").hostname
        return (host or target).strip().rstrip(".")

    def _query(self, resolver: dns.resolver.Resolver, host: str, rtype: str) -> list[str] | None:
        """Resolve *rtype* for *host*, returning string answers or None.

        TXT records are unquoted: dnspython's str() keeps the surrounding
        double quotes, which would break ``v=spf1`` prefix matching.
        """
        try:
            answers = resolver.resolve(host, rtype)
            values = [str(r).rstrip(".") for r in answers]
            if rtype == "TXT":
                values = [v.strip('"') for v in values]
            return values
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout,
            dns.exception.Timeout,
        ):
            return None
        except Exception as exc:  # noqa: BLE001
            logger.debug("DNS %s query failed for %s: %s", rtype, host, exc)
            return None

    def run(self) -> None:
        """Enumerate records and run the mail-security checks."""
        self.clear_findings()
        self.validate_options()

        host = self._strip_to_host(str(self.get_option("target")))
        timeout = float(self.get_option("timeout") or 5)
        attempt_axfr = bool(self.get_option("attempt_axfr") or False)

        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            task = progress.add_task(f"Enumerating DNS records for {host}", total=None)
            self._progress = progress

            results: dict[str, list[str] | None] = {}
            for rtype in RECORD_TYPES:
                results[rtype] = self._query(resolver, host, rtype)

            # --- Record enumeration (INFO) ---
            for rtype, values in results.items():
                if not values:
                    continue
                preview = "; ".join(values[:6])
                self.add_finding(
                    finding_type="DNS",
                    severity="INFO",
                    title=f"{rtype} records for {host}",
                    detail=f"{len(values)} {rtype} record(s): {preview}",
                    evidence=f"{host} {rtype}: {'; '.join(values[:10])}",
                )

            # --- Mail security: only meaningful when the host receives mail ---
            mx = results.get("MX") or []
            txt = results.get("TXT") or []
            if mx:
                has_spf = any(t.lower().startswith("v=spf1") for t in txt)
                if not has_spf:
                    self.add_finding(
                        finding_type="DNS",
                        severity="MEDIUM",
                        title=f"No SPF record for {host} (mail domain)",
                        detail=(
                            "The host has MX records (accepts mail) but no 'v=spf1' TXT record, "
                            "allowing anyone to spoof email from this domain."
                        ),
                        evidence=f"MX: {'; '.join(mx[:5])}\nTXT records found: {len(txt)}",
                    )
                has_dmarc = bool(self._query(resolver, f"_dmarc.{host}", "TXT"))
                if not has_dmarc:
                    self.add_finding(
                        finding_type="DNS",
                        severity="MEDIUM",
                        title=f"No DMARC record for {host} (mail domain)",
                        detail=(
                            f"The host has MX records but no DMARC policy at _dmarc.{host}, so "
                            f"receivers cannot enforce SPF/DKIM alignment against spoofing."
                        ),
                        evidence=f"MX: {'; '.join(mx[:5])}\n_dmarc.{host}: no TXT record",
                    )

            # --- Optional intrusive AXFR ---
            if attempt_axfr:
                for ns in results.get("NS") or []:
                    try:
                        zone = dns.zone.from_xfr(dns.query.xfr(ns, host, timeout=timeout))
                        names = [str(n) for n in zone.nodes.keys()][:20]
                        logger.warning("AXFR succeeded against %s (%d records leaked)", ns, len(zone.nodes))
                        self.add_finding(
                            finding_type="DNS",
                            severity="MEDIUM",
                            title=f"DNS zone transfer (AXFR) allowed by {ns}",
                            detail=(
                                f"The nameserver {ns} allowed a full zone transfer, "
                                f"disclosing the entire DNS layout of {host}."
                            ),
                            evidence=(
                                f"AXFR {host} @{ns}: {len(zone.nodes)} records; "
                                f"sample: {', '.join(names[:10])}"
                            ),
                        )
                        break  # one successful AXFR is enough to demonstrate
                    except Exception as exc:  # noqa: BLE001 — AXFR refused is the expected case
                        logger.debug("AXFR against %s failed (expected): %s", ns, exc)

            progress.update(task, completed=True)

        total = len(self.get_findings())
        logger.info("DNS records audit complete: %d finding(s).", total)
