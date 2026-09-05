#!/usr/bin/env python3
"""SUBDOMAINX command line launcher.

Run ``python subdomainx.py example.com`` from the project root.  This thin
wrapper simply delegates to :func:`subdomainx.cli.main` so that the tool can be
used straight from a clone without installing anything::

    pip install -r requirements.txt
    python subdomainx.py example.com --resolve --probe
"""

from __future__ import annotations

import os
import sys


def _bootstrap() -> None:
    """Make sure the project root is importable when run as a script."""
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)


def main() -> int:
    """Entry point used by ``python subdomainx.py``."""
    _bootstrap()
    from subdomainx.cli import main as cli_main

    return cli_main()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:  # pragma: no cover - user abort
        print("\nInterrupted.", file=sys.stderr)
        raise SystemExit(130)
