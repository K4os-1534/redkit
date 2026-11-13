"""Allow running RedKit via ``python -m redkit``."""

import sys

from redkit.cli import main

if __name__ == "__main__":
    sys.exit(main())
