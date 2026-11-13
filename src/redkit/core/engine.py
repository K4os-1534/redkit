"""
core/engine.py — Module discovery and loading engine for RedKit.

Discovers BaseModule subclasses in two places:

1. The bundled ``redkit/modules/`` package directory (shipped modules).
2. An optional ``./modules`` directory relative to the current working
   directory (user-provided modules — drop a file in a category
   subdirectory and restart).

Modules with a duplicate display name are skipped (bundled wins), so a
user can inspect what ships without name collisions breaking the browser.
"""

import importlib.util
import inspect
import logging
import sys
from pathlib import Path
from typing import Any

from redkit.modules.base_module import BaseModule

logger = logging.getLogger(__name__)

# Bundled modules directory inside the installed redkit package
_MODULES_DIR = Path(__file__).resolve().parent.parent / "modules"


class Engine:
    """Discovers, imports, and manages all RedKit modules.

    Usage::

        engine = Engine(config)
        engine.discover()
        for module in engine.get_all_modules():
            print(module.name)
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """Initialise the engine with an empty module registry.

        Args:
            config: Global configuration dict injected into every module
                instance at discovery time.
        """
        self._config: dict[str, Any] = config if isinstance(config, dict) else {}
        # Flat list of all discovered module instances
        self._modules: list[BaseModule] = []
        # Category → list of module instances
        self._by_category: dict[str, list[BaseModule]] = {}

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def discover(self) -> None:
        """Find and instantiate every BaseModule subclass.

        Scans the bundled modules directory first, then an optional
        ``./modules`` directory in the current working directory.
        """
        logger.debug("Starting module discovery.")
        self._modules.clear()
        self._by_category.clear()

        self._discover_tree(_MODULES_DIR, module_prefix="redkit._bundled_mod_")

        external_dir = Path.cwd() / "modules"
        if external_dir.is_dir() and external_dir != _MODULES_DIR:
            before = len(self._modules)
            self._discover_tree(external_dir, module_prefix="redkit._ext_mod_")
            logger.info(
                "External module discovery in %s: %d additional module(s).",
                external_dir,
                len(self._modules) - before,
            )

        total = len(self._modules)
        logger.info(
            "Module discovery complete: %d module(s) found across %d categories.",
            total,
            len(self._by_category),
        )

    def _discover_tree(self, root: Path, module_prefix: str) -> None:
        """Import every BaseModule subclass below *root*.

        Args:
            root: Directory to walk recursively.
            module_prefix: Prefix for synthetic module names (keeps bundled
                and external modules apart in sys.modules).
        """
        if not root.is_dir():
            return

        for py_file in sorted(root.rglob("*.py")):
            relative = py_file.relative_to(root)

            # Skip package inits and the abstract base
            if py_file.name in ("__init__.py", "base_module.py"):
                continue

            # Determine category from the immediate subdirectory name
            category = relative.parts[0] if len(relative.parts) > 1 else "misc"

            self._load_module_file(py_file, category, module_prefix)

    def _load_module_file(self, path: Path, category: str, module_prefix: str) -> None:
        """Import a single Python file and extract BaseModule subclasses from it.

        Args:
            path: Absolute path to the Python file.
            category: Category label derived from the subdirectory name.
            module_prefix: Prefix for the synthetic module name.
        """
        module_name = f"{module_prefix}{path.stem}_{category}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                logger.warning("Could not create spec for %s — skipping.", path)
                return

            py_module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = py_module
            spec.loader.exec_module(py_module)

            for _attr_name, obj in inspect.getmembers(py_module, inspect.isclass):
                if issubclass(obj, BaseModule) and obj is not BaseModule and obj.__module__ == module_name:
                    instance = self._instantiate(obj)
                    if any(m.name.lower() == instance.name.lower() for m in self._modules):
                        logger.debug(
                            "Skipping duplicate module name '%s' from %s.",
                            instance.name,
                            path,
                        )
                        continue
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

    def _instantiate(self, cls: type[BaseModule]) -> BaseModule:
        """Instantiate a module class, injecting config when supported.

        Args:
            cls: BaseModule subclass.

        Returns:
            Instantiated module.
        """
        try:
            return cls(config=self._config)
        except TypeError:
            # Third-party module with a custom __init__ that takes no config
            logger.debug("Module class %s does not accept config — instantiating bare.", cls.__name__)
            return cls()

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

    def get_module_by_name(self, name: str) -> BaseModule | None:
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

    def get_module_by_index(self, index: int) -> BaseModule | None:
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
