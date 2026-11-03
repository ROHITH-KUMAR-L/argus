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
    sub.add_parser("preflight", help="check that protected execution is available on this host")
    args = parser.parse_args(argv)

    if args.command == "config":
        print(json.dumps(load_settings().redacted(), indent=2))
        return 0
    if args.command == "preflight":
        from controller import preflight

        rep = preflight.run()
        print(json.dumps({"ok": rep.ok, "checks": rep.checks, "details": rep.details}, indent=2))
        return 0 if rep.ok else 1
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
