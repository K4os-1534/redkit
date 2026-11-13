# Security Policy

## Scope

This policy covers vulnerabilities **in RedKit itself** — the code in this
repository. Issues found *while using RedKit against an authorized target*
(things RedKit detects during a test) are findings for that engagement, not
security reports here.

## Supported versions

| Version | Supported |
|---------|-----------|
| 2.0.x   | ✅ |
| 1.x     | ❌ |

## Reporting a vulnerability

Please report security issues in RedKit privately:

1. Open a private security advisory via
   [GitHub Security Advisories](https://github.com/K4os-1534/redkit/security/advisories/new), or
2. Use [GitHub's private vulnerability reporting](https://github.com/K4os-1534/redkit/security) if advisories are unavailable.

**Do not open a public issue for a security problem.**

Include: affected version, reproduction steps or PoC, and your assessment of
impact. You will get an acknowledgement within 7 days and a status update
within 30 days. Credit is given in the changelog unless you prefer otherwise.

## Design notes for reviewers

RedKit is an offensive testing tool; some behaviour is deliberate:

- TLS certificate verification is **on by default** and only disabled via an
  explicit `verify_ssl: false` in config.yaml.
- Environment proxies are ignored; only the configured `proxy` is used.
- Requests and redirects are scope-checked against the target host.
- Credentials discovered during a scan are written to findings/reports (that
  is the tool's purpose) but are never written to the log file in plaintext.
- Report HTML escapes all finding content (findings carry attacker-controlled
  data by design).
