"""
core/engine.py — Module discovery and loading engine for RedKit.

Walks the modules/ directory, imports every Python module file, and
finds all classes that inherit from BaseModule.  Provides a registry
for looking up modules by name and iterating by category.
"""

import importlib.util
import inspect
import logging
import sys
from pathlib import Path
from typing import Optional

from modules.base_module import BaseModule

logger = logging.getLogger(__name__)

# Root of the project (one level above this file)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_MODULES_DIR = _PROJECT_ROOT / "modules"


class Engine:
    """Discovers, imports, and manages all RedKit modules.

    Usage::

        engine = Engine()
        engine.discover()
        for module in engine.get_all_modules():
            print(module.name)
    """

    def __init__(self) -> None:
        """Initialise the engine with an empty module registry."""
        # Flat list of all discovered module instances
        self._modules: list[BaseModule] = []
        # Category → list of module instances
        self._by_category: dict[str, list[BaseModule]] = {}

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def discover(self) -> None:
        """Walk the modules/ directory and import every BaseModule subclass.

        Skips __init__.py files and the base_module.py file itself.
        Organises discovered modules by subdirectory (= category).
        """
        logger.debug("Starting module discovery in: %s", _MODULES_DIR)
        self._modules.clear()
        self._by_category.clear()

        for py_file in sorted(_MODULES_DIR.rglob("*.py")):
            relative = py_file.relative_to(_MODULES_DIR)
            parts = relative.parts

            # Skip package inits and the abstract base
            if py_file.name in ("__init__.py", "base_module.py"):
                continue

            # Determine category from the immediate subdirectory name
            category = parts[0] if len(parts) > 1 else "misc"

            self._load_module_file(py_file, category)

        total = len(self._modules)
        logger.info(
            "Module discovery complete: %d module(s) found across %d categories.",
            total,
            len(self._by_category),
        )

    def _load_module_file(self, path: Path, category: str) -> None:
        """Import a single Python file and extract BaseModule subclasses from it.

        Args:
            path: Absolute path to the Python file.
            category: Category label derived from the subdirectory name.
        """
        module_name = f"redkit_mod_{path.stem}_{category}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                logger.warning("Could not create spec for %s — skipping.", path)
                return

            py_module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = py_module
            spec.loader.exec_module(py_module)  # type: ignore[attr-defined]

            for _attr_name, obj in inspect.getmembers(py_module, inspect.isclass):
                if (
                    issubclass(obj, BaseModule)
                    and obj is not BaseModule
                    and obj.__module__ == module_name
                ):
                    instance: BaseModule = obj()
                    instance.category = category
                    self._modules.append(instance)
                    self._by_category.setdefault(category, []).append(instance)
                    logger.debug(
                        "Loaded module '%s' (category=%s) from %s.",
                        instance.name,
                        category,
                        path.name,
                    )

        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to load module from %s: %s", path, exc, exc_info=True)

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def get_all_modules(self) -> list[BaseModule]:
        """Return every discovered module instance as a flat list.

        Returns:
            List of instantiated BaseModule subclasses.
        """
        return list(self._modules)

    def get_modules_by_category(self) -> dict[str, list[BaseModule]]:
        """Return modules grouped by category name.

        Returns:
            Dict mapping category string to list of module instances.
        """
        return dict(self._by_category)

    def get_module_by_name(self, name: str) -> Optional[BaseModule]:
        """Find a module by its display name (case-insensitive).

        Args:
            name: The module's display name.

        Returns:
            The matching BaseModule instance, or None if not found.
        """
        name_lower = name.lower()
        for mod in self._modules:
            if mod.name.lower() == name_lower:
                return mod
        return None

    def get_module_by_index(self, index: int) -> Optional[BaseModule]:
        """Return a module by its 1-based index in the flat module list.

        Args:
            index: 1-based position as displayed in the module browser.

        Returns:
            The module instance, or None if index is out of range.
        """
        try:
            return self._modules[index - 1]
        except IndexError:
            return None

    def count(self) -> int:
        """Return the total number of discovered modules.

        Returns:
            Integer count.
        """
        return len(self._modules)
