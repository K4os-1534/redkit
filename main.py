"""
main.py — RedKit entry point.

Parses optional CLI arguments (--target, --module) for quick launch,
bootstraps the session, engine, and TUI, and starts the interactive loop.
"""

import argparse
import logging
import sys
from pathlib import Path

import yaml

# -----------------------------------------------------------------------
# Project root on sys.path so relative imports resolve regardless of CWD
# -----------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from core.engine import Engine
from core.session import Session
from core.tui import TUI


def _setup_logging(config: dict) -> None:
    """Configure the root logger to write DEBUG output to a log file.

    Args:
        config: Parsed config.yaml dictionary.
    """
    log_file = _PROJECT_ROOT / config.get("log_file", "redkit.log")
    log_level = getattr(logging, config.get("log_level", "DEBUG").upper(), logging.DEBUG)

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
        ],
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


def _load_config() -> dict:
    """Load and return the config.yaml dictionary.

    Falls back to sensible defaults if the file is missing or unreadable.

    Returns:
        Configuration dict.
    """
    config_path = _PROJECT_ROOT / "config.yaml"
    defaults = {
        "default_threads": 10,
        "default_timeout": 5,
        "default_user_agent": "RedKit/1.0 (Authorized Security Testing)",
        "output_dir": "reports/",
        "max_findings_display": 50,
        "version": "1.0.0",
        "log_file": "redkit.log",
        "log_level": "DEBUG",
    }
    try:
        with open(config_path, "r", encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
            return {**defaults, **loaded}
    except FileNotFoundError:
        return defaults
    except Exception as exc:
        print(f"[WARN] Could not parse config.yaml: {exc} — using defaults.")
        return defaults


def _parse_args() -> argparse.Namespace:
    """Parse optional CLI arguments.

    Returns:
        Parsed argparse Namespace.
    """
    parser = argparse.ArgumentParser(
        prog="redkit",
        description="RedKit — Modular web red-teaming framework.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py\n"
            "  python main.py --target https://example.com\n"
            "  python main.py --target https://example.com --module 'XSS Tester'\n"
        ),
    )
    parser.add_argument(
        "--target", "-t",
        metavar="URL",
        help="Pre-set the target URL and skip the Set Target prompt.",
    )
    parser.add_argument(
        "--module", "-m",
        metavar="NAME",
        help="Pre-select a module by name and skip the Module Browser.",
    )
    return parser.parse_args()


def main() -> None:
    """Bootstrap RedKit and launch the TUI event loop."""
    config = _load_config()
    _setup_logging(config)
    logger = logging.getLogger(__name__)
    logger.info("RedKit starting up.")

    args = _parse_args()

    # Initialise core components
    session = Session()
    engine = Engine()
    engine.discover()

    # Apply CLI pre-population
    if args.target:
        try:
            session.set_target(args.target)
            logger.info("CLI target pre-set: %s", args.target)
        except ValueError as exc:
            print(f"[Error] Invalid target: {exc}")
            sys.exit(1)

    if args.module:
        module = engine.get_module_by_name(args.module)
        if module is None:
            print(f"[Error] Module '{args.module}' not found.")
            available = [m.name for m in engine.get_all_modules()]
            print("Available modules:", ", ".join(available))
            sys.exit(1)
        session.set_active_module(module)
        # Pre-fill target option if module has one
        if "target" in module.options and session.target:
            module.set_option("target", session.target)
        logger.info("CLI module pre-set: %s", args.module)

    # Launch TUI
    tui = TUI(session=session, engine=engine, config=config)
    try:
        tui.run()
    except KeyboardInterrupt:
        print("\n\n[bold red]Exiting RedKit…[/bold red] Stay safe and hack ethically.")
        logger.info("RedKit terminated by user (KeyboardInterrupt).")
        sys.exit(0)


if __name__ == "__main__":
    main()
