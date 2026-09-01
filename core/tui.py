"""
core/tui.py — Full interactive TUI for RedKit, built with the Rich library.

Provides the main menu loop, module browser, options panel, live progress
display, findings viewer, and all user-input prompts.
"""

import logging
import sys
import time
from typing import Any, Optional

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

logger = logging.getLogger(__name__)

console = Console()

# Severity → Rich colour mapping
SEVERITY_COLOURS: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "bold dark_orange",
    "MEDIUM": "bold yellow",
    "LOW": "bold blue",
    "INFO": "white",
}

_BANNER = r"""
 ____           _ _  ___ _   
|  _ \ ___  __| | |/ (_) |_ 
| |_) / _ \/ _` | ' /| | __|
|  _ <  __/ (_| | . \| | |_ 
|_| \_\___|\__,_|_|\_\_|\__|
"""

_VERSION = "v1.0.0"
_DISCLAIMER_LINE = "[dim]For authorized penetration testing and educational use ONLY.[/dim]"


class TUI:
    """Interactive Terminal User Interface for RedKit.

    Owns the main menu event loop and delegates to the engine and session
    for business logic. All user interaction is via Rich Prompt, all errors
    are displayed in styled Rich error panels.

    Args:
        session: Initialised Session instance.
        engine: Initialised and discovered Engine instance.
        config: Parsed config.yaml dict.
    """

    def __init__(self, session: Any, engine: Any, config: dict[str, Any]) -> None:
        """Initialise the TUI with references to session, engine, and config.

        Args:
            session: Active Session instance.
            engine: Module discovery Engine instance.
            config: Global config dict loaded from config.yaml.
        """
        self.session = session
        self.engine = engine
        self.config = config

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
        """Display the RedKit ASCII art banner."""
        console.clear()
        banner_text = Text(_BANNER, style="bold red", justify="center")
        version_text = Text(f"  {_VERSION}  |  Modular Web Red-Teaming Framework", style="bold white", justify="center")
        console.print(Align.center(banner_text))
        console.print(Align.center(version_text))
        console.print(Align.center(Text(_DISCLAIMER_LINE, justify="center")))
        console.print()

    # ------------------------------------------------------------------
    # Status bar
    # ------------------------------------------------------------------

    def _show_status_bar(self) -> None:
        """Print a status bar showing current target and active module."""
        target = self.session.target or "[dim]Not set[/dim]"
        module_name = self.session.active_module.name if self.session.active_module else "[dim]None selected[/dim]"
        grid = Table.grid(expand=True)
        grid.add_column(justify="left")
        grid.add_column(justify="right")
        grid.add_row(
            f"[bold green]Target:[/bold green] {target}",
            f"[bold cyan]Module:[/bold cyan] {module_name}",
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
            ("4", "View Findings"),
            ("5", "Generate Report"),
            ("6", "Exit"),
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
            "4": self._menu_view_findings,
            "5": self._menu_generate_report,
            "6": self._exit,
        }
        handler = handlers.get(choice)
        if handler:
            handler()
        else:
            self._error(f"Invalid option: '{choice}'. Choose 1–6.")

    # ------------------------------------------------------------------
    # Menu handlers
    # ------------------------------------------------------------------

    def _menu_set_target(self) -> None:
        """Prompt the user for a target URL and store it in the session."""
        console.print(Rule("[bold cyan]Set Target[/bold cyan]"))
        url = Prompt.ask("[bold white]Enter target URL[/bold white]", console=console).strip()
        try:
            normalised = self.session.set_target(url)
            console.print(f"[bold green]✔ Target set:[/bold green] {normalised}")
        except ValueError as exc:
            self._error(str(exc))
        self._pause()

    def _menu_select_module(self) -> None:
        """Show the module browser and let the user choose a module."""
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

        choice = Prompt.ask("\n[bold white]Select module number (or 'q' to cancel)[/bold white]", console=console).strip()
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
            console.print(f"\n[bold green]✔ Selected:[/bold green] {selected.name}")
            self._show_options_panel(selected)
        except ValueError:
            self._error("Please enter a valid number.")

        self._pause()

    def _show_options_panel(self, module: Any) -> None:
        """Display a module's current options and allow the user to configure them.

        Args:
            module: The selected BaseModule instance.
        """
        console.print(Rule(f"[bold cyan]Options — {module.name}[/bold cyan]"))
        while True:
            table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold white")
            table.add_column("Option", style="bold yellow", min_width=20)
            table.add_column("Value", style="cyan", min_width=25)
            table.add_column("Required", style="white", width=10)
            table.add_column("Description", style="dim")

            for key, meta in module.options.items():
                val = str(meta.get("value") or "[dim]Not set[/dim]")
                req = "[red]Yes[/red]" if meta.get("required") else "No"
                table.add_row(key, val, req, meta.get("description", ""))

            console.print(table)
            console.print(
                "\n[dim]Enter option name to set, or press Enter to continue:[/dim]"
            )
            opt_name = Prompt.ask("[bold white]Option[/bold white]", console=console, default="").strip()
            if not opt_name:
                break
            if opt_name not in module.options:
                self._error(f"Unknown option '{opt_name}'.")
                continue
            val_input = Prompt.ask(f"[bold white]Value for '{opt_name}'[/bold white]", console=console).strip()
            try:
                module.set_option(opt_name, val_input)
                console.print(f"[green]✔ Set {opt_name} = {val_input}[/green]")
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

    def _menu_run_module(self) -> None:
        """Validate and run the currently selected module, showing live progress."""
        if not self.session.active_module:
            self._error("No module selected. Use option [2] to select one.")
            self._pause()
            return

        module = self.session.active_module

        # Safety net: sync target in case target was set after module selection
        self._sync_target_to_module(module)

        try:
            module.validate_options()
        except ValueError as exc:
            self._error(str(exc))
            self._pause()
            return

        console.print(Rule(f"[bold red]Running: {module.name}[/bold red]"))
        console.print(f"[dim]Target: {module.get_option('target') if 'target' in module.options else 'N/A'}[/dim]\n")

        # Each module manages its own progress display internally.
        # Do not add a second outer Progress context here.
        try:
            module.run()
        except Exception as exc:  # noqa: BLE001
            self._error(f"Module error: {exc}")
            logger.error("Module '%s' raised an exception: %s", module.name, exc, exc_info=True)
            self._pause()
            return


        findings = module.get_findings()
        self.session.add_findings(module.name, findings)

        console.print(f"\n[bold green]✔ Scan complete.[/bold green] {len(findings)} finding(s) recorded.\n")
        if findings:
            self._render_findings_table(findings)
        self._pause()

    def _menu_view_findings(self) -> None:
        """Display all session findings in a colour-coded Rich table."""
        console.print(Rule("[bold cyan]Session Findings[/bold cyan]"))
        findings = self.session.get_all_findings()
        if not findings:
            console.print("[dim]No findings recorded yet.[/dim]")
        else:
            max_display = self.config.get("max_findings_display", 50)
            displayed = findings[:max_display]
            self._render_findings_table(displayed, show_module=True)
            if len(findings) > max_display:
                console.print(f"[dim]... and {len(findings) - max_display} more. Generate a report for the full list.[/dim]")
        self._pause()

    def _render_findings_table(
        self, findings: list[dict[str, Any]], show_module: bool = False
    ) -> None:
        """Render a Rich table of findings with colour-coded severity.

        Args:
            findings: List of finding dicts.
            show_module: Whether to include a 'Module' column.
        """
        table = Table(box=box.ROUNDED, show_header=True, header_style="bold white", expand=True)
        table.add_column("Severity", width=12)
        table.add_column("Type", style="dim", width=14)
        table.add_column("Title")
        if show_module:
            table.add_column("Module", style="dim", width=20)

        for finding in findings:
            sev = finding.get("severity", "INFO").upper()
            colour = SEVERITY_COLOURS.get(sev, "white")
            sev_text = Text(sev, style=colour)
            row = [sev_text, finding.get("type", ""), finding.get("title", "")]
            if show_module:
                row.append(finding.get("module", ""))
            table.add_row(*row)

        console.print(table)

    def _menu_generate_report(self) -> None:
        """Generate JSON and HTML reports for the current session."""
        from core.report import Reporter

        findings = self.session.get_all_findings()
        if not findings:
            self._error("No findings to report. Run a module first.")
            self._pause()
            return

        console.print(Rule("[bold cyan]Generating Report[/bold cyan]"))
        try:
            reporter = Reporter(self.session.export_session())
            json_path, html_path = reporter.generate()
            console.print(f"[bold green]✔ JSON:[/bold green] {json_path}")
            console.print(f"[bold green]✔ HTML:[/bold green] {html_path}")
        except Exception as exc:  # noqa: BLE001
            self._error(f"Report generation failed: {exc}")
            logger.error("Report generation error: %s", exc, exc_info=True)

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
        """Wait for the user to press Enter before returning to the menu."""
        console.print()
        Prompt.ask("[dim]Press Enter to continue[/dim]", console=console, default="")
        console.clear()
        self._show_banner()

    def _exit(self) -> None:
        """Print exit message and terminate the process."""
        console.print("\n[bold red]Exiting RedKit…[/bold red] Stay safe and hack ethically.\n")
        sys.exit(0)
