# RedKit

A modular, menu-driven web application red-teaming tool written in Python. Built around a Rich TUI, it groups common pentesting tasks — recon, vulnerability scanning, and auth testing — into a single interactive interface with session-based finding tracking and report generation.

> **Only use against systems you have explicit written permission to test.**

---

## Installation

```bash
git clone https://github.com/yourusername/redkit.git
cd redkit
pip install -r requirements.txt
```

To install as a system command:

```bash
pip install -e .
```

---

## Usage

Launch the interactive TUI:

```bash
python main.py
```

Skip straight to a module with CLI flags:

```bash
python main.py --target https://example.com --module "XSS Tester"
```

The main menu walks you through the workflow: set a target, pick a module, configure its options, run it, review findings, and generate a report. Findings accumulate across multiple module runs within the same session.

---

## Modules

| Category | Module | What it does |
|----------|--------|--------------|
| recon | Subdomain Enumerator | DNS A-record resolution against a wordlist |
| recon | Directory Brute-Forcer | HTTP GET brute-force with custom-404 baseline filtering |
| recon | Technology Fingerprinter | Detects tech stack from response headers, cookies, and HTML |
| vuln_scan | XSS Tester | Tests a parameter for reflected XSS using 15+ payloads |
| vuln_scan | SQLi Tester | Error-based and time-based blind SQL injection detection |
| vuln_scan | LFI Tester | Path traversal with 30+ payloads and signature-based confirmation |
| auth | Login Brute-Forcer | POST-based password brute-force, stops on first success |
| auth | Default Credentials Checker | Tests 28 common default credential pairs |

---

## Reports

After running one or more modules, select **Generate Report** from the menu. Two files are written to `reports/`:

- `redkit_{domain}_{timestamp}.json` — raw findings dump
- `redkit_{domain}_{timestamp}.html` — self-contained dark-themed report with expandable finding cards

---

## Configuration

`config.yaml` controls global defaults:

```yaml
default_threads: 10
default_timeout: 5
default_user_agent: "RedKit/1.0 (Authorized Security Testing)"
output_dir: "reports/"
max_findings_display: 50
```

---

## Writing a Module

RedKit auto-discovers any class inheriting from `BaseModule` in the `modules/` directory tree. No registration needed — just drop a file in the right subdirectory and restart.

```
modules/
└── recon/          ← or vuln_scan/, auth/, or a new category
    └── my_module.py
```

Minimal example:

```python
from modules.base_module import BaseModule
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

class MyModule(BaseModule):
    name        = "My Module"
    description = "One-line description shown in the module browser."
    author      = "you"
    category    = "recon"  # must match the subdirectory name

    options = {
        "target": {
            "value": None,
            "required": True,
            "description": "Target URL.",
        },
    }

    def run(self) -> None:
        self.clear_findings()
        self.validate_options()
        target = self.get_option("target")

        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      TimeElapsedColumn()) as progress:
            task = progress.add_task(f"Scanning {target}", total=None)
            # ... your logic ...
            progress.update(task, completed=True)

        self._add_finding(
            finding_type="Example",
            severity="HIGH",       # CRITICAL / HIGH / MEDIUM / LOW / INFO
            title="Something found",
            detail="Full explanation of the finding.",
            evidence="Raw request, response snippet, or matched string.",
        )
```

---

## Legal

For authorized penetration testing and educational use only. See [DISCLAIMER.md](DISCLAIMER.md).
