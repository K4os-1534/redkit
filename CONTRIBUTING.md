# Contributing to RedKit

Thanks for your interest in contributing! RedKit is a security testing tool built for authorized use — please read the [disclaimer](DISCLAIMER.md) first.

## Ground rules

- **Authorized use only.** Contributions that add capabilities explicitly designed for unauthorized access, denial of service, or data exfiltration will be rejected.
- Discuss big changes in an issue before writing significant code.
- Every change must come with tests, and CI must stay green.

## Development setup

Requires Python 3.10+.

```bash
git clone https://github.com/K4os-1534/redkit.git
cd redkit
python -m venv venv && source venv/bin/activate
pip install -e ".[dev]"
pre-commit install          # optional but recommended
```

## Running the checks

```bash
pytest                      # test suite
pytest --cov=redkit         # with coverage
ruff check src tests        # lint
ruff format --check src tests
mypy                        # type check
python -m build             # build sdist + wheel
```

The exact same checks run in [CI](.github/workflows/ci.yml) on Python 3.10–3.14.

## Project layout

```
src/redkit/
├── cli.py               # argument parsing, TUI/headless dispatch
├── core/
│   ├── config.py        # config.yaml loading + defaults
│   ├── engine.py        # module discovery (bundled + ./modules)
│   ├── history.py       # recent targets + last-used module options
│   ├── http_client.py   # shared HTTP client (scope, TLS, proxy, rate limit)
│   ├── models.py        # Severity enum + Finding dataclass + remediation KB
│   ├── profiles.py      # scan profiles (builtins + profiles.yaml)
│   ├── report.py        # JSON/HTML report generation
│   ├── resources.py     # bundled wordlist/template paths
│   ├── session.py       # target, findings, save/resume
│   └── tui.py           # interactive menu (Rich)
├── modules/
│   ├── base_module.py   # module API — subclass this
│   ├── auth/            # authentication testing modules
│   ├── misconfig/       # security-misconfiguration audit modules
│   ├── recon/           # reconnaissance modules
│   └── vuln_scan/       # vulnerability scanning modules
├── templates/           # report.html.j2
└── wordlists/           # bundled wordlists
tests/                   # pytest suite
```

## Writing a module

See the [Writing a Module](README.md#writing-a-module) section in the README for the full guide. Quick checklist:

1. Create `src/redkit/modules/<category>/my_module.py` (bundled) or `./modules/<category>/my_module.py` (external).
2. Subclass `BaseModule`; define `name`, `description`, `author`, `category` (must match the subdirectory), and `options`.
3. Implement `run()`: `clear_findings()` → `validate_options()` → do the work via `self.http_client(target)` → `self.add_finding(...)`.
4. Use honest severities and wording — "potential" for unconfirmed issues.
5. Never log plaintext credentials or other secrets.
6. Set `self._progress = progress` inside your Progress block so findings
   echo to the live feed; pass `cvss=` for confirmed vulnerabilities.
7. Add tests in `tests/test_modules_*.py` using the `make_response` fixture and a patched `HttpClient.request`.

## Pull requests

- Create a feature branch; keep PRs focused.
- Add or update tests for any behavior change.
- Update [CHANGELOG.md](CHANGELOG.md) under "Unreleased".
- The PR template will remind you of the checklist.

## Reporting issues

- Bug reports: use the [bug template](.github/ISSUE_TEMPLATE/bug_report.md) and include your RedKit version, Python version, OS, and the `redkit.log` excerpt (redact any sensitive target data).
- Feature ideas: use the [feature template](.github/ISSUE_TEMPLATE/feature_request.md).
- Security issues in RedKit itself: see [SECURITY.md](SECURITY.md) — please do not open public issues for them.
