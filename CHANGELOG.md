# Changelog

All notable changes to RedKit are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-11-14

Full production-readiness release: package restructure, shared HTTP layer,
correctness fixes for the original 8 modules, a complete UX overhaul of the
TUI, and **19 new modules** (27 total) — every module verified against a
controlled multi-endpoint test site (39/39 positive/negative checks) and
against a live OWASP Juice Shop instance (all Juice Shop challenges detected,
zero false positives).

The import surface changed
(`from modules.base_module import …` → `from redkit.modules.base_module import …`),
hence the major version bump.

### Added

#### New modules (19)

- **recon**: Subdomain Takeover Checker (dangling CNAME + vendor fingerprints),
  DNS Records Auditor (records, SPF/DMARC for mail domains, optional AXFR),
  robots.txt & Sitemap Harvester, JavaScript Analyzer (keys, source maps,
  internal hosts), Historical URLs via the Wayback CDX API.
- **vuln_scan**: SSTI Tester (unique arithmetic markers), Command Injection
  Tester (time-based with baseline + retest), XXE Tester (in-band file
  disclosure), SSRF Tester (cloud metadata via strong response signatures),
  Open Redirect Tester (Location-header canary host), CRLF Injection Tester
  (canary response headers, single/double-encoded + Unicode variants).
- **misconfig** (new category): Security Headers Auditor, Cookie Auditor,
  CORS Tester, Sensitive File Disclosure (signature + soft-404 double
  filtering), API Docs Exposure, GraphQL Introspection.
- **auth**: Username Enumerator (message/size/timing differential; timing is
  INFO only), HTTP Basic Brute-Forcer (gated on 401 + WWW-Authenticate).
- Every finding type ships remediation guidance; confirmed vulnerabilities
  carry CVSS v3.1 base scores with vector comments in the source.

#### Architecture & UX

- Shared HTTP client (`redkit.core.http_client`): configurable UA, TLS
  verification **on by default**, proxy support, per-host rate limiting,
  connection-error retries, scope-checked manual redirect following,
  custom headers/cookies. Environment proxies are ignored.
- Scope guard: requests and redirect hops to hosts outside the target are
  refused (`enforce_scope` opt-out exists only for modules consulting
  third-party archive APIs).
- Headless CLI mode: `--no-tui`, `--opt KEY=VALUE`, `--no-report`, `--save`
  (frozen scripting surface; the TUI is the primary interface).
- Session persistence: `Session.save()`/`load()`, TUI **[7] Save Session**,
  `redkit --resume <file>`, `redkit --last`.
- `--version`, `--list-modules`, `--help-options`, `--init-config`,
  `--verbose`, fuzzy module matching.
- Structured findings: `Severity` enum + `Finding` dataclass; public
  `BaseModule.add_finding()` (with `_add_finding` alias).
- Option type metadata with coercion/validation; config injected into every
  module by the engine (no per-module config.yaml reads).
- External module discovery from `./modules/` (bundled wins on name clashes).
- TUI: main menu 1–8 with **Run Profile** (built-in + `profiles.yaml` scan
  profiles with option carry-over), findings browser with severity bars,
  `s`/`m` filters and a detail view, live finding feed, recent targets and
  last-used options (`~/.redkit/history.json`), run-now flow with inline
  missing-option prompts, per-session authorization confirmation, auth-attack
  confirmation, `ui_pause`/`ui_clear_screen` (scrollback preserved by
  default), enriched status bar.
- Reports: self-contained HTML (escaped evidence, CVSS badges, remediation),
  Markdown export, JSON dump — all honoring `output_dir`.
- Test suite (168 tests), GitHub Actions CI (Python 3.10–3.14: ruff, mypy,
  pytest, pip-audit, wheel build + smoke), Dependabot, pre-commit, Dockerfile.
- `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, issue/PR templates.

### Changed

- **Packaging**: src-layout package (`src/redkit/`) with `pyproject.toml`
  (PEP 621) replacing `setup.py`/`requirements.txt`; version single-sourced;
  wordlists/templates resolved via package resources (wheels work anywhere).
- **Dependencies**: `requests>=2.32.0` (CVE-2024-35195), `jinja2>=3.1.5`
  (CVE-2024-56201/CVE-2024-56326); removed unused `aiohttp`/`httpx`.
- SQLi tester: benign-baseline error suppression, adaptive time threshold,
  mandatory retest (reproducible → CRITICAL, one-off → INFO).
- XSS tester: de-duplicated per parameter with HTML-context classification;
  comment-only reflection is MEDIUM; verbatim reflection is reported as
  *potential*.
- Login brute-forcer / default-credentials checker: failed-login baseline
  (2xx **and 401** responses accepted), redirect + non-2xx handling.
- HTML report autoescaping unconditional (`select_autoescape` silently
  disabled escaping for `.j2` templates — a stored-XSS-in-report bug).
- Reports directory follows `output_dir`; report footer carries the real
  package version (previously hardcoded v1.0.0).

### Fixed

- Login brute-forcer tried wordlist comment lines as passwords.
- Plaintext credentials no longer written to `redkit.log`.
- Wayback module now passes its `timeout` option to the HTTP request.
- Misc: unused imports, duplicate dead branch in dir brute-force severity
  mapping, filename sanitisation deduplicated between Session and Reporter.

## [1.0.0] - 2026-09-01

Initial release: Rich TUI, module auto-discovery engine, 8 modules
(recon / vuln_scan / auth), session findings, JSON+HTML reports.

[2.0.0]: https://github.com/K4os-1534/redkit/releases/tag/v2.0.0
[1.0.0]: https://github.com/K4os-1534/redkit/releases/tag/v1.0.0
