"""
core/resources.py — Bundled resource paths (wordlists, report templates).

Resolves files shipped inside the ``redkit`` package so they work both from
a source checkout and from an installed wheel / editable install. Regular
pip installs unpack the package as a plain directory, so path-based access
is safe for every supported install mode.
"""

from pathlib import Path

#: Directory of the installed redkit package (…/site-packages/redkit or src/redkit)
PACKAGE_DIR = Path(__file__).resolve().parent.parent


def package_path(*parts: str) -> Path:
    """Return a path to a resource inside the redkit package.

    Args:
        parts: Path segments relative to the package root.

    Returns:
        Absolute path to the resource.
    """
    return PACKAGE_DIR.joinpath(*parts)


def default_wordlist(name: str) -> Path:
    """Return the path to a bundled wordlist file.

    Args:
        name: Filename inside the wordlists directory (e.g. "directories.txt").

    Returns:
        Path to the wordlist.
    """
    return package_path("wordlists", name)


def templates_dir() -> Path:
    """Return the directory containing the report Jinja2 templates.

    Returns:
        Path to the templates directory.
    """
    return package_path("templates")
