"""
core/models.py — Shared data models and knowledge base for RedKit findings.

Modules produce :class:`Finding` objects; sessions, reports, and session
files all consume the same model so severity handling, remediation advice,
and serialisation stay consistent across the tool.
"""

import logging
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    """Severity levels for findings, from most to least severe."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def parse(cls, value: object) -> "Severity":
        """Convert an arbitrary value to a Severity, defaulting to INFO.

        Args:
            value: Severity name (any case) or Severity instance.

        Returns:
            Parsed Severity (INFO when the value is not recognised).
        """
        if isinstance(value, Severity):
            return value
        try:
            return cls(str(value).upper())
        except ValueError:
            logger.warning("Unknown severity '%s' — falling back to INFO.", value)
            return cls.INFO


#: Rich markup styles for each severity, shared by the TUI, the live
#: finding feed, and the headless renderer.
SEVERITY_STYLES: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "bold dark_orange",
    "MEDIUM": "bold yellow",
    "LOW": "bold blue",
    "INFO": "white",
}

#: Short remediation guidance per finding type, included in reports and the
#: TUI finding-detail view. Unknown types get an empty string.
REMEDIATION: dict[str, str] = {
    "SQL Injection": (
        "Use parameterised queries / prepared statements for every database "
        "access; never build SQL by string concatenation. Validate and "
        "type-cast input server-side, apply least-privilege DB accounts, and "
        "suppress verbose DB errors in production responses."
    ),
    "SQL Injection (Blind)": (
        "As with error-based SQLi: parameterised queries everywhere. Time-based "
        "injection works even without visible errors, so also rate-limit "
        "suspicious request patterns and monitor for anomalous query latency."
    ),
    "XSS": (
        "HTML-encode output in its correct context (HTML body, attribute, or "
        "JS), use templating engines with autoescaping, apply a strict Content "
        "Security Policy, and validate/normalise user input server-side."
    ),
    "LFI": (
        "Never pass user-supplied paths directly to file APIs. Maintain an "
        "allowlist of includable files, resolve paths against a fixed base "
        "directory and reject traversal, and disable remote-file wrappers "
        "(e.g. PHP allow_url_include)."
    ),
    "Directory/File": (
        "Restrict access to sensitive paths with authentication/authorization, "
        "disable directory listing, remove unused files and admin endpoints "
        "from production, and return uniform 404 responses."
    ),
    "Subdomain": (
        "Review each discovered host: decommission stale subdomains (shadow "
        "IT is a common entry point), ensure all hosts use HTTPS, and keep "
        "DNS records tidy to limit takeover surface."
    ),
    "Technology": (
        "Minimise technology disclosure (remove Server/X-Powered-By headers), "
        "keep frameworks and libraries patched, and hide version-specific "
        "artefacts such as generator meta tags."
    ),
    "Authentication": (
        "Enforce account lockout or exponential back-off after failed "
        "attempts, require strong passwords and MFA, use generic login error "
        "messages, and monitor for credential-stuffing patterns."
    ),
    "Default Credentials": (
        "Immediately change all default and well-known credentials, disable "
        "unused accounts, rotate shared passwords, and add MFA to "
        "administrative interfaces."
    ),
    "SSTI": (
        "Never pass user input directly into template engines. Use "
        "data-binding APIs (pass values as context variables) instead of "
        "string-templating user input, and sandbox or disable dangerous "
        "template features where supported."
    ),
    "Open Redirect": (
        "Validate redirect destinations against an allowlist of trusted "
        "hosts or use relative-path-only redirects; never echo a raw URL "
        "parameter into Location headers or redirect APIs."
    ),
    "Command Injection": (
        "Avoid invoking OS shells with user input. Use language-native "
        "library calls instead of shell commands; where unavoidable, pass "
        "arguments as arrays (no shell interpolation) and allowlist values."
    ),
    "CRLF Injection": (
        "Reject CR/LF control characters in any value echoed into response "
        "headers, use framework header APIs that reject header injection, "
        "and encode user data before placing it in header values."
    ),
    "XXE": (
        "Disable external entity and DTD processing in the XML parser "
        "(e.g. defusedxml, JVM setFeature disallow-doctype-decl), and "
        "prefer JSON where feasible."
    ),
    "SSRF": (
        "Validate outbound fetch URLs against an allowlist of schemes and "
        "hosts, block requests to link-local/metadata/private IP ranges "
        "(including after DNS resolution and redirects), and run outbound "
        "fetchers without cloud-credential access."
    ),
    "Security Headers": (
        "Add the missing hardening headers: a strict Content-Security-Policy, "
        "HSTS for HTTPS sites, X-Frame-Options/frame-ancestors, "
        "X-Content-Type-Options: nosniff, a Referrer-Policy, and a "
        "Permissions-Policy. Validate with a header-audit tool after deploy."
    ),
    "Cookie Security": (
        "Set Secure and HttpOnly flags and an explicit SameSite attribute "
        "(Lax or Strict) on every session cookie, and scope cookie paths "
        "and domains as narrowly as possible."
    ),
    "CORS": (
        "Do not reflect arbitrary Origin headers. Maintain a server-side "
        "allowlist of origins, and never combine reflected or wildcard "
        "origins with Access-Control-Allow-Credentials: true."
    ),
    "Sensitive File": (
        "Remove secrets and repository metadata from the web root, block "
        "access to dotfiles and backup files at the web server/CDN level, "
        "rotate any credentials found in exposed files immediately, and "
        "disable framework debug endpoints in production."
    ),
    "API Documentation": (
        "Restrict API documentation endpoints (Swagger UI, OpenAPI JSON) to "
        "authenticated internal users or remove them from production "
        "entirely; documentation reveals the full attack surface."
    ),
    "GraphQL": (
        "Disable introspection in production, add depth/complexity limits "
        "and query cost analysis, and require authorization per resolver."
    ),
    "Subdomain Takeover": (
        "Remove the dangling DNS record or re-provision the abandoned "
        "service under the same name, and continuously monitor for CNAMEs "
        "pointing at deprovisioned cloud resources."
    ),
    "DNS": (
        "Publish SPF and DMARC records for every domain that sends or may "
        "appear to send email, restrict DNS zone transfers, and review "
        "MX/NS records for stale or unnecessary entries."
    ),
    "robots.txt": (
        "Do not rely on robots.txt to hide sensitive paths — it is public "
        "by design. Enforce authentication on any path listed there and "
        "remove entries that disclose internal structure."
    ),
    "JavaScript Analysis": (
        "Remove API keys and secrets from client-side code (rotate any "
        "exposed keys immediately), keep secrets server-side, and do not "
        "deploy source maps to production."
    ),
    "Historical URLs": (
        "Review each historical endpoint: ensure retired URLs return 404/410 "
        "without content, and that old endpoints still resolve do not bypass "
        "current authentication or expose stale data."
    ),
    "Username Enumeration": (
        "Return identical error messages, response sizes, and timing for "
        "existing and non-existing accounts, and apply uniform rate "
        "limiting to authentication endpoints."
    ),
    "HTTP Basic Auth": (
        "Replace HTTP Basic authentication with a session/token-based "
        "mechanism served over HTTPS; where Basic must remain, enforce "
        "strong passwords, MFA at the gateway, and account lockout."
    ),
}


def remediation_for(finding_type: str) -> str:
    """Return remediation guidance for a finding type (empty if unknown).

    Args:
        finding_type: The finding's type label.

    Returns:
        Remediation text, or "" when the type has no guidance.
    """
    return REMEDIATION.get(finding_type, "")


@dataclass
class Finding:
    """A single structured result produced by a RedKit module."""

    type: str
    severity: Severity
    title: str
    detail: str
    evidence: str = ""
    module: str = ""
    timestamp: str = ""
    cvss: float | None = None

    def __post_init__(self) -> None:
        """Normalise the severity to a Severity enum member."""
        self.severity = Severity.parse(self.severity)

    def to_dict(self) -> dict[str, object]:
        """Return the plain-dict form used by reports and session files.

        Returns:
            Dict with all finding fields (severity as its string value).
        """
        return {
            "type": self.type,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
            "module": self.module,
            "timestamp": self.timestamp,
            "cvss": self.cvss,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "Finding":
        """Build a Finding from a plain dict (tolerant of missing fields).

        Args:
            data: Dict as produced by :meth:`to_dict` or a legacy finding dict.

        Returns:
            Reconstructed Finding.
        """
        raw_cvss = data.get("cvss")
        try:
            cvss = float(raw_cvss) if raw_cvss is not None else None  # type: ignore[arg-type]
        except (TypeError, ValueError):
            cvss = None
        return cls(
            type=str(data.get("type", "")),
            severity=Severity.parse(data.get("severity", "INFO")),
            title=str(data.get("title", "")),
            detail=str(data.get("detail", "")),
            evidence=str(data.get("evidence", "")),
            module=str(data.get("module", "")),
            timestamp=str(data.get("timestamp", "")),
            cvss=cvss,
        )
