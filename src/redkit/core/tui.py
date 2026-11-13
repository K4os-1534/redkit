"""
core/tui.py — Full interactive TUI for RedKit, built with the Rich library.

Provides the main menu loop, module browser, options panel, live progress
display, findings viewer (with detail view and filtering), scan profiles,
session save, and all user-input prompts.

Behaviour is configurable via config.yaml:

- ``ui_pause``: wait for Enter after each action (default: true)
- ``ui_clear_screen``: clear the screen and re-render the banner between
  actions (default: false — scrollback is preserved)
- ``live_feed``: echo findings to the console as they are discovered
- ``ask_authorization``: confirm written permission before the first scan
- ``save_history``: remember recent targets and last-used module options
"""

import logging
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, urlparse

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from redkit import __version__
from redkit.core.history import (
    history_path,
    load_module_options,
    recent_targets,
    record_module_options,
    record_target,
)
from redkit.core.models import SEVERITY_STYLES, Finding, remediation_for
from redkit.core.profiles import load_profiles, resolve_profile

logger = logging.getLogger(__name__)

console = Console()

_BANNER = r"""
  ____           _ _  ___ _
 |  _ \ ___  __| | |/ (_) |_
 | |_) / _ \/ _` | ' /| | __|
 |  _ <  __/ (_| | . \| | |_
 |_| \_\___|\__,_|_|\_\_|\__|
"""

_VERSION = f"v{__version__}"

_DISCLAIMER_LINE = "[dim]For authorized penetration testing and educational use ONLY.[/dim]"

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def render_findings_table(
    console: Console,
    findings: list[Finding],
    show_module: bool = False,
    max_rows: int | None = None,
    show_index: bool = False,
) -> None:
    """Render a Rich table of findings with colour-coded severity.

    Shared by the interactive TUI and the headless CLI mode.

    Args:
        console: Rich console to print to.
        findings: List of Finding objects.
        show_module: Whether to include a 'Module' column.
        max_rows: Maximum number of rows to render (None = all).
        show_index: Whether to include a 1-based index column (used by the
            TUI findings browser for the detail view).
    """
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold white", expand=True)
    if show_index:
        table.add_column("#", style="dim", width=5)
    table.add_column("Severity", width=12)
    table.add_column("Type", style="dim", width=14)
    table.add_column("Title")
    if show_module:
        table.add_column("Module", style="dim", width=20)

    rows = findings[:max_rows] if max_rows is not None else findings
    for i, finding in enumerate(rows, 1):
        colour = SEVERITY_STYLES.get(finding.severity.value, "white")
        row: list[Any] = []
        if show_index:
            row.append(str(i))
        row += [
            Text(finding.severity.value, style=colour),
            finding.type,
            finding.title,
        ]
        if show_module:
            row.append(finding.module)
        table.add_row(*row)

    console.print(table)


class TUI:
    """Interactive Terminal User Interface for RedKit.

    Owns the main menu event loop and delegates to the engine and session
    for business logic. All user interaction is via Rich Prompt, all errors
    are displayed in styled Rich error panels.

    Args:
        session: Initialised Session instance.
        engine: Initialised and discovered Engine instance.
        config: Merged RedKit configuration dict.
    """

    def __init__(self, session: Any, engine: Any, config: dict[str, Any]) -> None:
        """Initialise the TUI with references to session, engine, and config.

        Args:
            session: Active Session instance.
            engine: Module discovery Engine instance.
            config: Global config dict.
        """
        self.session = session
        self.engine = engine
        self.config = config
        #: Whether the user confirmed written permission for this session.
        self._authorization_confirmed = False

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Launch the main interactive menu loop."""
        self._show_banner()
        while True:
            try:
                self._show_status_bar()
                self._show_main_menu()
                choice = Prompt.ask("[bold cyan]Select option[/bold cyan]", console=console).strip()
                self._handle_main_menu(choice)
            except KeyboardInterrupt:
                self._exit()
                break

    # ------------------------------------------------------------------
    # Banner
    # ------------------------------------------------------------------

    def _show_banner(self) -> None:
        """Display the RedKit ASCII art banner (clearing only when configured)."""
        if self.config.get("ui_clear_screen", False):
            console.clear()
        banner_text = Text(_BANNER.strip("\n"), style="bold red")
        version_text = Text(
            f"  {_VERSION}  |  Modular Web Red-Teaming Framework",
            style="bold white",
            justify="center",
        )
        console.print(Align.center(banner_text))
        console.print()
        console.print(Align.center(version_text))
        console.print(Align.center(Text(_DISCLAIMER_LINE, justify="center")))
        console.print()

    # ------------------------------------------------------------------
    # Status bar
    # ------------------------------------------------------------------

    def _show_status_bar(self) -> None:
        """Print a status bar: target, module, findings summary, uptime, HTTP settings."""
        target = self.session.target or "[dim]Not set[/dim]"
        module_name = (
            self.session.active_module.name if self.session.active_module else "[dim]None selected[/dim]"
        )

        counts = Counter(f.severity.value for f in self.session.get_all_findings())
        if counts:
            summary = " [dim]·[/dim] ".join(
                f"[{SEVERITY_STYLES[sev]}]{counts[sev]} {sev}[/{SEVERITY_STYLES[sev]}]"
                for sev in _SEVERITY_ORDER
                if counts.get(sev)
            )
        else:
            summary = "[dim]No findings yet[/dim]"

        uptime = datetime.now(timezone.utc) - self.session.start_time
        hours, remainder = divmod(int(uptime.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)

        extras: list[str] = []
        proxy = str(self.config.get("proxy") or "")
        if proxy:
            extras.append(f"[bold magenta]proxy[/bold magenta] {proxy}")
        rate_limit = float(self.config.get("rate_limit", 0.0) or 0.0)
        if rate_limit > 0:
            extras.append(f"[bold magenta]rate[/bold magenta] {rate_limit}s/host")

        grid = Table.grid(expand=True)
        grid.add_column(justify="left")
        grid.add_column(justify="right")
        grid.add_row(
            f"[bold green]Target:[/bold green] {target}",
            f"[bold cyan]Module:[/bold cyan] {module_name}",
        )
        grid.add_row(
            f"Findings: {summary}",
            f"[dim]up {hours:02d}:{minutes:02d}:{seconds:02d}[/dim]"
            + (f"  {', '.join(extras)}" if extras else ""),
        )
        console.print(Panel(grid, style="dim", box=box.ROUNDED))

    # ------------------------------------------------------------------
    # Main menu
    # ------------------------------------------------------------------

    def _show_main_menu(self) -> None:
        """Render the numbered main menu."""
        console.print(Rule("[bold red]Main Menu[/bold red]"))
        options = [
            ("1", "Set Target"),
            ("2", "Select Module"),
            ("3", "Run Module"),
            ("4", "Run Profile (module sequence)"),
            ("5", "View Findings"),
            ("6", "Generate Report"),
            ("7", "Save Session"),
            ("8", "Exit"),
        ]
        table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
        table.add_column(style="bold yellow", width=4)
        table.add_column(style="white")
        for num, label in options:
            table.add_row(f"[{num}]", label)
        console.print(table)

    def _handle_main_menu(self, choice: str) -> None:
        """Route the user's main menu selection to the appropriate handler.

        Args:
            choice: String digit entered by the user.
        """
        handlers = {
            "1": self._menu_set_target,
            "2": self._menu_select_module,
            "3": self._menu_run_module,
            "4": self._menu_run_profile,
            "5": self._menu_view_findings,
            "6": self._menu_generate_report,
            "7": self._menu_save_session,
            "8": self._exit,
        }
        handler = handlers.get(choice)
        if handler:
            handler()
        else:
            self._error(f"Invalid option: '{choice}'. Choose 1–8.")

    # ------------------------------------------------------------------
    # Menu handlers
    # ------------------------------------------------------------------

    def _menu_set_target(self) -> None:
        """Prompt the user for a target URL (offering recent targets) and store it."""
        console.print(Rule("[bold cyan]Set Target[/bold cyan]"))

        recents: list[str] = []
        if self.config.get("save_history", True):
            recents = recent_targets(history_path(self.config))
        if recents:
            console.print("[bold white]Recent targets:[/bold white]")
            for i, recent in enumerate(recents, 1):
                console.print(f"  [bold yellow][{i}][/] {recent}")
            console.print()

        raw = Prompt.ask(
            "[bold white]Enter target URL, a recent number, or blank to cancel[/bold white]",
            console=console,
            default="",
            show_default=False,
        ).strip()
        if not raw:
            console.print("[dim]Target unchanged.[/dim]")
            self._pause()
            return

        url = raw
        if raw.isdigit() and recents and 1 <= int(raw) <= len(recents):
            url = recents[int(raw) - 1]

        try:
            normalised = self.session.set_target(url)
            console.print(f"[bold green]✔ Target set:[/bold green] {normalised}")
            record_target(
                history_path(self.config), normalised, enabled=self.config.get("save_history", True)
            )
        except ValueError as exc:
            self._error(str(exc))
        self._pause()

    def _menu_select_module(self) -> None:
        """Show the module browser, configure the module, and offer to run it now."""
        console.print(Rule("[bold cyan]Module Browser[/bold cyan]"))
        modules = self.engine.get_all_modules()
        if not modules:
            self._error("No modules discovered. Check the modules/ directory.")
            return

        categories = self.engine.get_modules_by_category()

        global_index = 1
        index_map: dict[int, Any] = {}

        for category, mods in categories.items():
            console.print(f"\n[bold yellow]  {category.upper()}[/bold yellow]")
            table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold white")
            table.add_column("#", style="dim", width=4)
            table.add_column("Name", style="bold cyan", min_width=25)
            table.add_column("Description", style="white")
            table.add_column("Author", style="dim", min_width=15)

            for mod in mods:
                table.add_row(str(global_index), mod.name, mod.description, mod.author)
                index_map[global_index] = mod
                global_index += 1

            console.print(table)

        choice = Prompt.ask(
            "\n[bold white]Select module number (or 'q' to cancel)[/bold white]",
            console=console,
        ).strip()
        if choice.lower() == "q":
            return

        try:
            idx = int(choice)
            selected = index_map.get(idx)
            if selected is None:
                self._error(f"No module at index {idx}.")
                return
            self.session.set_active_module(selected)
            # ── Pre-populate target from session so the options panel renders
            # the correct value immediately rather than showing "Not set".
            self._sync_target_to_module(selected)
            self._restore_previous_options(selected)
            console.print(f"\n[bold green]✔ Selected:[/bold green] {selected.name}")
            self._show_options_panel(selected)

            run_now = Prompt.ask(
                "\n[bold white]Run this module now?[/bold white]",
                console=console,
                choices=["y", "n"],
                default="y",
                show_default=False,
            )
            if run_now == "y":
                self._execute_module(selected)
        except ValueError:
            self._error("Please enter a valid number.")

        self._pause()

    def _restore_previous_options(self, module: Any) -> None:
        """Pre-fill unset options with the module's last-used values.

        Args:
            module: The selected BaseModule instance.
        """
        if not self.config.get("save_history", True):
            return
        saved = load_module_options(history_path(self.config), module.name)
        restored = 0
        for key, value in saved.items():
            if key in module.options and module.options[key]["value"] in (None, ""):
                try:
                    module.set_option(key, value)
                    restored += 1
                except (KeyError, ValueError):
                    continue
        if restored:
            console.print(f"[dim]Restored {restored} previously used option(s) for this module.[/dim]")

    def _show_options_panel(self, module: Any) -> None:
        """Display a module's current options and allow the user to configure them.

        Args:
            module: The selected BaseModule instance.
        """
        console.print(Rule(f"[bold cyan]Options — {module.name}[/bold cyan]"))
        while True:
            table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold white")
            table.add_column("Option", style="bold yellow", min_width=16)
            table.add_column("Value", style="cyan", min_width=22)
            table.add_column("Type", style="dim", width=8)
            table.add_column("Required", style="white", width=10)
            table.add_column("Description", style="dim")

            for key, meta in module.options.items():
                val = str(meta.get("value") if meta.get("value") is not None else "[dim]Not set[/dim]")
                declared = meta.get("type")
                type_label = declared.__name__ if declared else "str"
                req = "[red]Yes[/red]" if meta.get("required") else "No"
                table.add_row(key, val, type_label, req, meta.get("description", ""))

            console.print(table)

            hints = self._target_param_hints()
            if "param" in module.options and not module.options["param"]["value"] and hints:
                console.print(f"[dim]Hint: target URL contains parameter(s): {', '.join(hints)}[/dim]")

            console.print("\n[dim]Enter option name to set, or press Enter to continue:[/dim]")
            opt_name = Prompt.ask("[bold white]Option[/bold white]", console=console, default="").strip()
            if not opt_name:
                break
            if opt_name not in module.options:
                self._error(f"Unknown option '{opt_name}'.")
                continue
            val_input = Prompt.ask(
                f"[bold white]Value for '{opt_name}'[/bold white]", console=console
            ).strip()
            try:
                module.set_option(opt_name, val_input)
                console.print(f"[green]✔ Set {opt_name} = {module.get_option(opt_name)}[/green]")
            except Exception as exc:  # noqa: BLE001
                self._error(str(exc))

    def _sync_target_to_module(self, module: Any) -> None:
        """Inject the session target into a module's 'target' option if not already set.

        Called both when selecting a module (so the options panel shows the
        pre-populated value) and just before running (as a safety net in case
        the target was set after the module was selected).

        Args:
            module: The active BaseModule instance to update.
        """
        if "target" in module.options and not module.options["target"]["value"]:
            if self.session.target:
                module.set_option("target", self.session.target)
                logger.debug(
                    "Auto-populated target='%s' into module '%s'.",
                    self.session.target,
                    module.name,
                )

    def _target_param_hints(self) -> list[str]:
        """Return query-parameter names found in the session target URL.

        Returns:
            List of parameter names (may be empty).
        """
        if not self.session.target:
            return []
        try:
            return list(parse_qs(urlparse(self.session.target).query).keys())
        except (ValueError, TypeError):  # pragma: no cover — defensive
            return []

    def _prompt_missing_options(self, module: Any) -> bool:
        """Interactively prompt for required options that are still unset.

        Args:
            module: The BaseModule about to run.

        Returns:
            True when all required options are set (or were filled in),
            False when the user cancelled.
        """
        hints = self._target_param_hints()
        for key, meta in module.options.items():
            if not (meta.get("required") and meta.get("value") in (None, "")):
                continue
            description = meta.get("description", "")
            prompt = f"[bold white]{key}[/bold white] is required — {description}"
            if key == "param" and hints:
                prompt += f" [dim](found in target: {', '.join(hints)})[/dim]"
            value = Prompt.ask(prompt, console=console, default="", show_default=False).strip()
            if not value:
                self._error(f"Cancelled — required option '{key}' was not set.")
                return False
            try:
                module.set_option(key, value)
            except (KeyError, ValueError) as exc:
                self._error(str(exc))
                return False
        return True

    def _confirm_authorization(self) -> bool:
        """Confirm written permission before the first scan of a session.

        Returns:
            True when authorization is confirmed (or prompting is disabled).
        """
        if not self.config.get("ask_authorization", True):
            return True
        if self._authorization_confirmed or not self.session.target:
            return self._authorization_confirmed or not self.session.target
        answer = Prompt.ask(
            f"[bold yellow]Confirm[/bold yellow] you have written permission to test"
            f" [bold]{self.session.target}[/bold]",
            console=console,
            choices=["y", "n"],
            default="n",
            show_default=False,
        )
        if answer == "y":
            self._authorization_confirmed = True
            return True
        self._error("Scan cancelled — authorization was not confirmed.")
        return False

    def _confirm_auth_attack(self, module: Any) -> bool:
        """Confirm before running authentication-attack modules.

        Args:
            module: The BaseModule about to run.

        Returns:
            True when the user accepted the attack.
        """
        if module.category != "auth":
            return True
        target = module.get_option("target") if "target" in module.options else self.session.target
        answer = Prompt.ask(
            f"[bold yellow]Warning:[/bold yellow] '{module.name}' performs an authentication"
            f" attack against [bold]{target}[/bold] and may lock out accounts. Continue?",
            console=console,
            choices=["y", "n"],
            default="n",
            show_default=False,
        )
        if answer == "y":
            return True
        console.print("[yellow]Module skipped.[/yellow]")
        return False

    def _execute_module(self, module: Any) -> None:
        """Validate, confirm, and run a single module; record its findings.

        Args:
            module: The BaseModule instance to execute.
        """
        # Safety net: sync target in case it was set after module selection
        self._sync_target_to_module(module)

        if not self._prompt_missing_options(module):
            return
        try:
            module.validate_options()
        except ValueError as exc:
            self._error(str(exc))
            return
        if not self._confirm_authorization():
            return
        if not self._confirm_auth_attack(module):
            return

        console.print(Rule(f"[bold red]Running: {module.name}[/bold red]"))
        target_value = module.get_option("target") if "target" in module.options else "N/A"
        console.print(f"[dim]Target: {target_value}[/dim]\n")

        # Each module manages its own progress display internally.
        # Do not add a second outer Progress context here.
        try:
            module.run()
        except Exception as exc:  # noqa: BLE001
            self._error(f"Module error: {exc}")
            logger.error("Module '%s' raised an exception: %s", module.name, exc, exc_info=True)
            return

        findings = module.get_findings()
        self.session.add_findings(module.name, findings)

        record_module_options(
            history_path(self.config),
            module.name,
            module.options,
            enabled=self.config.get("save_history", True),
        )

        console.print(f"\n[bold green]✔ Scan complete.[/bold green] {len(findings)} finding(s) recorded.\n")
        if findings:
            render_findings_table(console, findings)

    def _menu_run_module(self) -> None:
        """Run the currently selected module."""
        if not self.session.active_module:
            self._error("No module selected. Use option [2] to select one.")
            self._pause()
            return

        self._execute_module(self.session.active_module)
        self._pause()

    def _menu_run_profile(self) -> None:
        """List scan profiles and run the chosen one as a module sequence."""
        console.print(Rule("[bold cyan]Run Profile[/bold cyan]"))
        profiles = load_profiles()
        if not profiles:
            self._error("No profiles available.")
            self._pause()
            return

        table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold white")
        table.add_column("#", style="dim", width=4)
        table.add_column("Profile", style="bold cyan", min_width=22)
        table.add_column("Modules", style="white")
        for i, (name, module_names) in enumerate(profiles.items(), 1):
            table.add_row(str(i), name, " → ".join(module_names))
        console.print(table)

        choice = Prompt.ask(
            "\n[bold white]Select profile number (or 'q' to cancel)[/bold white]",
            console=console,
        ).strip()
        if choice.lower() == "q":
            return

        try:
            idx = int(choice)
            name = list(profiles.keys())[idx - 1]
        except (ValueError, IndexError):
            self._error("Please enter a valid profile number.")
            self._pause()
            return

        try:
            modules = resolve_profile(self.engine, name, profiles)
        except ValueError as exc:
            self._error(str(exc))
            self._pause()
            return
        if not self.session.target:
            self._error("No target set. Use option [1] to set one first.")
            self._pause()
            return

        console.print(Rule(f"[bold red]Profile: {name}[/bold red]"))
        shared: dict[str, Any] = {}
        total = 0

        for position, module in enumerate(modules, 1):
            console.print(f"\n[bold cyan]── [{position}/{len(modules)}] {module.name} ──[/bold cyan]")
            self._sync_target_to_module(module)

            # Carry over option values filled in for earlier modules in this
            # profile run (e.g. the same 'param' across vuln_scan modules).
            for key, value in shared.items():
                if key in module.options and module.options[key]["value"] in (None, ""):
                    try:
                        module.set_option(key, value)
                    except (KeyError, ValueError):
                        continue

            if not self._prompt_missing_options(module):
                self._error("Profile run cancelled.")
                break
            if not self._confirm_authorization():
                break
            if not self._confirm_auth_attack(module):
                continue

            try:
                module.validate_options()
            except ValueError as exc:
                self._error(f"Skipping {module.name}: {exc}")
                continue

            try:
                module.run()
            except Exception as exc:  # noqa: BLE001 — one failure must not stop the profile
                self._error(f"{module.name} failed: {exc}")
                logger.error("Profile module '%s' raised: %s", module.name, exc, exc_info=True)
                continue

            findings = module.get_findings()
            self.session.add_findings(module.name, findings)
            record_module_options(
                history_path(self.config),
                module.name,
                module.options,
                enabled=self.config.get("save_history", True),
            )
            for key, meta in module.options.items():
                if key != "target" and meta.get("value") not in (None, ""):
                    shared[key] = meta["value"]
            total += len(findings)
            console.print(f"[green]✔ {module.name}: {len(findings)} finding(s)[/green]")

        console.print(
            f"\n[bold green]✔ Profile '{name}' complete.[/bold green] {total} finding(s) recorded.\n"
        )
        self._pause()

    # ------------------------------------------------------------------
    # Findings viewer
    # ------------------------------------------------------------------

    def _render_severity_summary(self, findings: list[Finding]) -> None:
        """Print colour-coded severity counts with simple bars.

        Args:
            findings: Findings to summarise.
        """
        counts = Counter(f.severity.value for f in findings)
        total = len(findings)
        if not total:
            return
        bar_width = 24
        for sev in _SEVERITY_ORDER:
            n = counts.get(sev, 0)
            if not n:
                continue
            style = SEVERITY_STYLES.get(sev, "white")
            bar = "█" * max(1, round(n / total * bar_width))
            console.print(f"  [{style}]{sev:<9}[/{style}] {n:>3}  [{style}]{bar}[/{style}]")
        console.print()

    def _finding_detail_panel(self, finding: Finding, index: int) -> None:
        """Print the full detail view for one finding.

        Args:
            finding: The finding to display.
            index: 1-based position in the browsable list (for the title).
        """
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="dim", justify="right", min_width=11)
        grid.add_column()
        style = SEVERITY_STYLES.get(finding.severity.value, "white")
        grid.add_row("Severity", Text(finding.severity.value, style=style))
        grid.add_row("Type", finding.type)
        grid.add_row("Module", finding.module or "[dim]N/A[/dim]")
        grid.add_row("Timestamp", finding.timestamp or "[dim]N/A[/dim]")
        grid.add_row(
            "CVSS",
            str(finding.cvss) if finding.cvss is not None else "[dim]not scored[/dim]",
        )
        grid.add_row("Detail", finding.detail)
        if finding.evidence:
            grid.add_row("Evidence", Text(finding.evidence, style="green"))
        remediation = remediation_for(finding.type)
        if remediation:
            grid.add_row("Remediation", Text(remediation, style="green"))

        console.print(Panel(grid, title=f"Finding #{index}", box=box.ROUNDED, expand=True))

    def _menu_view_findings(self) -> None:
        """Browse session findings: summary, filters, and a detail view."""
        console.print(Rule("[bold cyan]Session Findings[/bold cyan]"))
        findings = self.session.get_all_findings()
        if not findings:
            console.print("[dim]No findings recorded yet.[/dim]")
            self._pause()
            return

        severity_filter: str | None = None
        module_filter: str | None = None

        while True:
            console.print()
            self._render_severity_summary(findings)
            active = []
            if severity_filter:
                active.append(f"severity={severity_filter}")
            if module_filter:
                active.append(f"module={module_filter}")
            if active:
                console.print(f"[dim]Filters active: {', '.join(active)} (c to clear)[/dim]\n")

            visible = [
                f
                for f in findings
                if (severity_filter is None or f.severity.value == severity_filter)
                and (module_filter is None or f.module == module_filter)
            ]
            if not visible:
                console.print("[dim]No findings match the active filters.[/dim]")
            else:
                max_display = int(self.config.get("max_findings_display", 50))
                render_findings_table(
                    console, visible, show_module=True, show_index=True, max_rows=max_display
                )
                if len(visible) > max_display:
                    remaining = len(visible) - max_display
                    console.print(f"[dim]... and {remaining} more (refine with filters).[/dim]")

            choice = Prompt.ask(
                "\n[bold white][#] details · s <SEV> · m <module> · c clear · Enter back[/bold white]",
                console=console,
                default="",
                show_default=False,
            ).strip()
            if not choice:
                break
            if choice.isdigit():
                idx = int(choice)
                if 1 <= idx <= len(visible):
                    console.print()
                    self._finding_detail_panel(visible[idx - 1], idx)
                    Prompt.ask("[dim]Press Enter to continue[/dim]", console=console, default="")
                else:
                    self._error(f"No finding #{idx} in the current view (1–{len(visible)}).")
            elif choice == "c":
                severity_filter = module_filter = None
            elif choice.startswith("s "):
                candidate = choice[2:].strip().upper()
                if candidate in _SEVERITY_ORDER:
                    severity_filter = candidate
                else:
                    self._error(f"Unknown severity '{candidate}'. Options: {', '.join(_SEVERITY_ORDER)}")
            elif choice.startswith("m "):
                candidate = choice[2:].strip()
                known = {f.module for f in findings if f.module}
                matched = next((m for m in known if m.lower() == candidate.lower()), None)
                if matched:
                    module_filter = matched
                else:
                    self._error(f"Unknown module '{candidate}'. Known: {', '.join(sorted(known)) or '—'}")
            else:
                self._error("Use a finding number, 's <SEVERITY>', 'm <module>', 'c', or press Enter.")

        self._pause()

    # ------------------------------------------------------------------
    # Reports and session persistence
    # ------------------------------------------------------------------

    def _menu_generate_report(self) -> None:
        """Generate JSON, HTML, and Markdown reports for the current session."""
        from redkit.core.report import Reporter

        findings = self.session.get_all_findings()
        if not findings:
            self._error("No findings to report. Run a module first.")
            self._pause()
            return

        console.print(Rule("[bold cyan]Generating Report[/bold cyan]"))
        try:
            reporter = Reporter(
                self.session.export_session(),
                output_dir=self.config.get("output_dir", "reports"),
            )
            json_path, html_path, md_path = reporter.generate()
            console.print(f"[bold green]✔ JSON:[/bold green] {json_path}")
            console.print(f"[bold green]✔ HTML:[/bold green] {html_path}")
            console.print(f"[bold green]✔ Markdown:[/bold green] {md_path}")
        except Exception as exc:  # noqa: BLE001
            self._error(f"Report generation failed: {exc}")
            logger.error("Report generation error: %s", exc, exc_info=True)

        self._pause()

    def _menu_save_session(self) -> None:
        """Prompt for a file path and save the session for later resumption."""
        console.print(Rule("[bold cyan]Save Session[/bold cyan]"))
        if not self.session.get_all_findings() and not self.session.target:
            self._error("Nothing to save — no target set and no findings recorded.")
            self._pause()
            return

        default_name = (
            f"redkit_session_{self.session.get_target_domain()}_"
            f"{datetime.now(tz=timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        )
        path = Prompt.ask(
            "[bold white]Save session to[/bold white]",
            console=console,
            default=default_name,
        ).strip()
        try:
            saved = self.session.save(path)
            console.print(f"[bold green]✔ Session saved:[/bold green] {saved}")
            console.print("[dim]Resume later with: redkit --resume " + str(saved) + "[/dim]")
        except (OSError, ValueError) as exc:
            self._error(f"Session save failed: {exc}")
            logger.error("Session save error: %s", exc, exc_info=True)

        self._pause()

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    def _error(self, message: str) -> None:
        """Display a styled error panel.

        Args:
            message: Error message to display.
        """
        console.print(Panel(f"[bold red]✖ Error:[/bold red] {message}", style="red", box=box.ROUNDED))

    def _pause(self) -> None:
        """Wait for Enter (optional) and redraw according to the UI config.

        Honours ``ui_pause`` and ``ui_clear_screen``: with the defaults the
        scrollback is preserved and only a thin separator is drawn.
        """
        console.print()
        if self.config.get("ui_pause", True):
            Prompt.ask("[dim]Press Enter to continue[/dim]", console=console, default="")
        if self.config.get("ui_clear_screen", False):
            self._show_banner()
        else:
            console.print(Rule(style="dim"))

    def _exit(self) -> None:
        """Print exit message and terminate the process."""
        console.print("\n[bold red]Exiting RedKit…[/bold red] Stay safe and hack ethically.\n")
        sys.exit(0)
