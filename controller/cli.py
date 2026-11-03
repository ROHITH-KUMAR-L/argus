"""Command-line entry point (``argus``). Subcommands are added phase by phase."""

from __future__ import annotations

import argparse
import json
import sys

from controller import __version__
from controller.config import load_settings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="argus", description="Argus controller CLI")
    parser.add_argument("--version", action="version", version=f"argus {__version__}")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("config", help="print the effective (redacted) controller settings")
    args = parser.parse_args(argv)

    if args.command == "config":
        print(json.dumps(load_settings().redacted(), indent=2))
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
