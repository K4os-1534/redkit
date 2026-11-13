# RedKit

[![CI](https://github.com/K4os-1534/redkit/actions/workflows/ci.yml/badge.svg)](https://github.com/K4os-1534/redkit/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-261230)](https://docs.astral.sh/ruff/)

A modular, menu-driven web application red-teaming framework written in Python. RedKit ships **27 modules** across recon, vulnerability scanning, misconfiguration auditing, and authentication testing, behind an interactive TUI, with scan profiles, session-based finding tracking, and report generation.

> **⚠️ Only use RedKit against systems you have explicit written permission to test.** Unauthorized testing is illegal in most jurisdictions. See [DISCLAIMER.md](DISCLAIMER.md).

---

## Features

- **Plugin architecture** — any `BaseModule` subclass dropped into `modules/<category>/` is discovered automatically. No registration.
- **Interactive TUI (primary interface)** — menus, options panels, live finding feed, findings browser with detail view and filters, scan profiles.
- **Frozen headless mode** — a minimal, stable `--no-tui` scripting surface for cron/CI; see [Headless mode](#headless-mode-frozen).
- **Scope guard** — HTTP requests and redirect hops are checked against the target host; payloads can't leak to out-of-scope systems via redirects.
- **Baseline calibration** — SQLi and login modules calibrate against benign requests first, so noisy pages, soft-404s, and slow servers don't produce false positives.
- **Findings model** — severity-typed findings with CVSS scores and remediation guidance; sessions can be saved and resumed.
- **Reporting** — self-contained dark-themed HTML report (escaped evidence), a Markdown report for pentest docs, and a raw JSON dump.
- **Configurable HTTP layer** — shared client with TLS-verify opt-in, proxy support (Burp/ZAP), rate limiting, retries, custom headers/cookies for authenticated testing.

## Demo

```text
  ____           _ _  ___ _
 |  _ \ ___  __| | |/ (_) |_
 | |_) / _ \/ _` | ' /| | __|
 |  _ <  __/ (_| | . \| | |_
 |_| \_\___|\__,_|_|\_\_|\__|

  v2.0.0  |  Modular Web Red-Teaming Framework
  For authorized penetration testing and educational use ONLY.

┌───────────────────────────────────────────────────────────────────────┐
│ Target: https://example.com        Module: XSS Tester                 │
│ Findings: 2 CRITICAL · 1 HIGH      up 00:12:34                        │
└───────────────────────────────────────────────────────────────────────┘
──────────────────────────── Main Menu ──────────────────────────────
 [1]  Set Target
 [2]  Select Module
 [3]  Run Module
 [4]  Run Profile (module sequence)
 [5]  View Findings
 [6]  Generate Report
 [7]  Save Session
 [8]  Exit
```

## Installation

Requires Python 3.10+.

```bash
git clone https://github.com/K4os-1534/redkit.git
cd redkit
python -m venv venv
source venv/bin/activate
pip install -e .
```

This installs a `redkit` console command. Alternatively, run from a checkout without installing:

```bash
pip install -e .   # or: pip install rich requests dnspython pyyaml jinja2
python -m redkit
```

> Wordlists and report templates are bundled inside the package — RedKit works from any working directory. A `config.yaml` in the current directory overrides the built-in defaults (generate one with `redkit --init-config`).

## Usage

### Interactive TUI

```bash
redkit
# or pre-set parts of the session:
redkit --target https://example.com --module "XSS Tester"
# resume a saved session:
redkit --resume redkit_session_example.com_20260101_120000.json
redkit --last          # resume the newest session file in this directory
```

The menu walks you through the workflow: set a target, pick a module, configure its options, run it, review findings, save the session, and generate a report. Findings accumulate across module runs within the same session.

Conveniences built into the TUI:

- **Recent targets** — the Set Target screen offers your last 10 targets.
- **Restored options** — modules remember their last-used option values.
- **Run now** — selecting a module offers to run it immediately; missing required options are prompted for inline (query-parameter names found in the target URL are suggested).
- **Live finding feed** — hits appear under the progress bar as they're found.
- **Findings browser** — colour-coded severity summary, `s <SEVERITY>` / `m <module>` filters, and a full detail view per finding (evidence, CVSS, remediation).
- **Safety prompts** — a one-time authorization confirmation per session before the first scan, and an explicit confirmation before authentication-attack modules. Both are configurable.

### Scan profiles

Menu **[4] Run Profile** executes a named sequence of modules in one action, carrying shared options between them (fill `param` once and all three vuln modules use it):

| Profile | Sequence |
|---------|----------|
| Quick Recon | Technology Fingerprinter → Directory Brute-Forcer |
| Full Recon | Subdomain Enumerator → Technology Fingerprinter → Directory Brute-Forcer |
| Vulnerability Sweep | XSS Tester → SQLi Tester → LFI Tester |

Define your own in a `profiles.yaml` file in the working directory:

```yaml
Night Shift:
  - Technology Fingerprinter
  - XSS Tester
```

### Headless mode (frozen)

```bash
redkit --no-tui --target https://example.com --module "SQLi Tester" \
       --opt param=id --save session.json
```

> The TUI is the product. Headless mode is a **minimal, frozen scripting surface**: it runs one module, prints its findings, writes reports, and exits — and its flags will not change, so scripts and CI can rely on it. New features land TUI-first.

Exit code is `0` on a completed run (regardless of findings), `1` on errors, `130` on interrupt.

### CLI reference

| Flag | Description |
|------|-------------|
| `--target, -t URL` | Pre-set the target URL |
| `--module, -m NAME` | Pre-select a module (exact or substring match, e.g. `xss`) |
| `--no-tui` | Headless scripting mode (requires `--target` and `--module`) — frozen |
| `--opt KEY=VALUE` | Set a module option; repeatable; headless mode only |
| `--no-report` | Headless mode: skip report generation |
| `--save PATH` | Headless mode: save the session to PATH after the run |
| `--resume PATH` | Resume a saved session file |
| `--last` | Resume the most recent session file in the current directory |
| `--list-modules` | List all discovered modules and exit |
| `--help-options` | With `--module NAME`: print that module's options table |
| `--init-config` | Write a commented config.yaml to the current directory |
| `--config, -c PATH` | Use an alternative config.yaml |
| `--verbose` | Mirror logs to stderr (stdout stays clean for scripts) |
| `--version` | Print version and exit |

## Modules

All findings carry honest severities, CVSS v3.1 base scores where confirmed, and remediation guidance.

| Category | Module | What it does |
|----------|--------|--------------|
| recon | Subdomain Enumerator | DNS A-record resolution against a wordlist |
| recon | Subdomain Takeover Checker | Dangling CNAME + vendor takeover fingerprints (signature-confirmed) |
| recon | DNS Records Auditor | A/AAAA/CNAME/MX/NS/TXT enumeration; SPF/DMARC checks for mail domains; optional AXFR |
| recon | Directory Brute-Forcer | Concurrent HTTP brute-force with custom-404 baseline filtering |
| recon | Technology Fingerprinter | Detects tech stack from response headers, cookies, and HTML |
| recon | robots.txt & Sitemap Harvester | Extracts hidden paths from robots.txt and sitemaps (soft-404 resistant) |
| recon | JavaScript Analyzer | Scans the site's JS for exposed keys, source maps, internal hosts |
| recon | Historical URLs (Wayback) | Historical endpoint discovery via the archive.org CDX API |
| vuln_scan | XSS Tester | Reflected XSS with HTML-context classification and de-duplication |
| vuln_scan | SQLi Tester | Error-based + time-based blind detection with baseline calibration and re-verification |
| vuln_scan | SSTI Tester | Server-side template injection via unique arithmetic markers (no verbatim-reflection FPs) |
| vuln_scan | Command Injection Tester | Blind OS command injection via time delays with baseline calibration and retests |
| vuln_scan | LFI Tester | Path traversal with 30+ payloads and signature-based confirmation |
| vuln_scan | XXE Tester | XML external entity file disclosure (in-band, signature-confirmed) |
| vuln_scan | SSRF Tester | Cloud-metadata SSRF via strong response signatures (never trusts reflection) |
| vuln_scan | Open Redirect Tester | Location-header analysis against an injected canary host (no request leaves the target) |
| vuln_scan | CRLF Injection Tester | Header injection via canary response headers (single/double-encoded + Unicode variants) |
| misconfig | Security Headers Auditor | Missing/weak CSP, HSTS, X-Frame-Options, nosniff, Referrer/Permissions-Policy |
| misconfig | Cookie Auditor | Missing Secure/HttpOnly/SameSite on Set-Cookie (session-aware severities) |
| misconfig | CORS Tester | Origin reflection / null-origin / wildcard+credentials (exact-echo matching) |
| misconfig | Sensitive File Disclosure | Exposed .git, .env, backups, debug endpoints — signature + soft-404 double filtering |
| misconfig | API Docs Exposure | Public Swagger/OpenAPI endpoints (signature-confirmed) |
| misconfig | GraphQL Introspection | GraphQL endpoints and introspection status |
| auth | Login Brute-Forcer | POST brute-force with failed-login baseline detection; stops on first success |
| auth | Default Credentials Checker | Tests 28 common default credential pairs |
| auth | Username Enumerator | Login message/size/timing differential analysis (timing = INFO only) |
| auth | HTTP Basic Brute-Forcer | Basic-auth brute-force, gated on 401 + WWW-Authenticate detection |

Findings are reported with honest severities and CVSS v3.1 base scores where confirmed: SQLi reflections that don't reproduce are INFO, comment-only XSS reflections are MEDIUM, takeover/cors/sensitive-file findings require both a DNS/content signature and baseline agreement, and module output distinguishes *confirmed* from *potential* — always manually verify before acting on a finding.

## Reports

Reports are written to the configured `output_dir` (default `./reports`):

- `redkit_{domain}_{timestamp}.json` — raw findings dump
- `redkit_{domain}_{timestamp}.html` — self-contained dark-themed report with expandable finding cards, CVSS badges, and remediation guidance; all finding content is HTML-escaped
- `redkit_{domain}_{timestamp}.md` — Markdown report for pasting into pentest documents

## Configuration

Place a `config.yaml` in the directory you run RedKit from (or pass `--config`; generate a starter with `--init-config`). Every key is optional:

```yaml
# --- Network ---
default_threads: 10          # concurrent workers for thread-pooled modules
default_timeout: 5           # HTTP timeout in seconds
default_user_agent: "RedKit/2.0.0 (Authorized Security Testing)"
verify_ssl: true             # validate TLS certificates (disable only for lab targets)
proxy: ""                    # e.g. "http://127.0.0.1:8080" to route through Burp/ZAP
rate_limit: 0.0              # minimum seconds between requests per host (0 = off)
max_retries: 0               # retries on connection errors per request (0 = off)
max_redirects: 10            # redirect hops followed per request
custom_headers: {}           # extra headers, e.g. { "Authorization": "Bearer ..." }
custom_cookies: {}           # cookies for authenticated testing

# --- TUI behaviour ---
ui_pause: true               # "Press Enter to continue" after each action
ui_clear_screen: false       # clear screen + banner between actions (default: keep scrollback)
live_feed: true              # echo findings to the console as they are discovered
ask_authorization: true      # confirm written permission before the first scan
save_history: true           # remember recent targets and last-used module options
history_file: ""             # override the default ~/.redkit/history.json

# --- Output ---
output_dir: "reports"
max_findings_display: 50

# --- Logging ---
log_file: "redkit.log"
log_level: "DEBUG"
```

Notes:

- TLS verification is **on by default**; disabling it is an explicit choice (`verify_ssl: false`).
- Environment proxies (`HTTP_PROXY` etc.) are ignored — only the configured `proxy` is used.
- Passwords found by the auth modules are recorded in findings/reports, but are never written to the log file in plaintext.
- History (`~/.redkit/history.json`) stores target URLs and non-secret option values only; set `save_history: false` to disable.

## Session persistence

Save mid-engagement and resume later:

- TUI: menu option **[7] Save Session**
- CLI: `--save session.json`
- Resume: `redkit --resume session.json` or `redkit --last`

## Writing a Module

RedKit auto-discovers any class inheriting from `BaseModule` in a `modules/<category>/` directory. Bundled modules live inside the package; **user modules** can be dropped into `./modules/<category>/` relative to your working directory — both are loaded, duplicates by name are skipped.

```
myproject/
└── modules/
    └── recon/          ← any subdirectory name = the category
        └── my_module.py
```

Minimal example:

```python
from redkit.modules.base_module import BaseModule
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn


class MyModule(BaseModule):
    name = "My Module"
    description = "One-line description shown in the module browser."
    author = "you"
    category = "recon"  # must match the subdirectory name

    options = {
        "target": {
            "value": None,
            "required": True,
            "description": "Target URL.",
        },
        "threads": {
            "value": 10,
            "required": False,
            "type": int,  # values from TUI/CLI are coerced to this type
            "description": "Concurrent threads.",
        },
    }

    def run(self) -> None:
        self.clear_findings()
        self.validate_options()
        target = self.get_option("target")

        # Shared HTTP client: UA, TLS, proxy, rate limit, retries, and a
        # scope guard tied to the target host all come from config.yaml.
        http = self.http_client(target)

        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      TimeElapsedColumn()) as progress:
            self._progress = progress  # enables the live finding feed
            task = progress.add_task(f"Scanning {target}", total=None)
            response = http.get(target)
            progress.update(task, completed=True)

        if response.status_code == 200:
            self.add_finding(
                finding_type="Example",
                severity="INFO",   # CRITICAL / HIGH / MEDIUM / LOW / INFO
                title="Something found",
                detail="Full explanation of the finding.",
                evidence="Raw request, response snippet, or matched string.",
                # cvss=7.5,  # optional CVSS v3.1 base score for confirmed vulns
            )
```

Module conventions:

- Call `self.clear_findings()` first and `self.validate_options()` before any network activity.
- Issue HTTP through `self.http_client(target)` — never raw `requests` calls — so scope checks, TLS policy, proxying, and rate limits apply.
- Set `self._progress = progress` inside your Progress block so findings echo to the live feed.
- Read global settings with `self.get_config(key, default)`; the config dict is injected by the engine.
- Bundled wordlists are available via `from redkit.core.resources import default_wordlist`.
- Handle exceptions inside `run()` — a module should never crash the TUI.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full development setup and pull-request process.

## Development

```bash
git clone https://github.com/K4os-1534/redkit.git
cd redkit
python -m venv venv && source venv/bin/activate
pip install -e ".[dev]"

pytest            # run the test suite
ruff check .      # lint
ruff format .     # format
mypy              # type check
```

CI runs the same checks on Python 3.10–3.14 on every push and pull request.

## Legal

For authorized penetration testing and educational use only. See [DISCLAIMER.md](DISCLAIMER.md) and [SECURITY.md](SECURITY.md). RedKit is MIT-licensed — see [LICENSE](LICENSE).
