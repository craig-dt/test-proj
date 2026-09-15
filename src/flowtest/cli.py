"""flowtest command-line entry point.

Exit codes (PRD 6.1): 0 success, 1 usage error, 2 input could not be read. Skipped rows never change the
exit code.
"""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Sequence

from flowtest.commands import COMMANDS
from flowtest.options import tool_version
from flowtest.reader import InputError


class Parser(argparse.ArgumentParser):
    """argparse exits 2 on usage errors; flowtest reserves 2 for unreadable input, so use 1."""

    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        sys.stderr.write(f"{self.prog}: error: {message}\n")
        raise SystemExit(1)


def build_parser() -> Parser:
    parser = Parser(
        prog="flowtest",
        description="Offline triage of NetFlow-style CSV exports: top talkers, top ports, beacons.",
    )
    parser.add_argument("--version", action="version", version=f"flowtest {tool_version()}")
    sub = parser.add_subparsers(dest="command", metavar="<command>", required=True)
    for module in COMMANDS:
        module.register(sub)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    start = time.perf_counter()
    try:
        return int(args.func(args, start))
    except InputError as exc:
        sys.stderr.write(f"flowtest: {exc}\n")
        return 2
    except BrokenPipeError:  # e.g. `flowtest ... | head`
        return 0
    except OSError as exc:  # I/O error mid-run (disk error, closing FIFO, full stdout): exit 2
        where = f"{exc.filename}: " if exc.filename else ""
        sys.stderr.write(f"flowtest: {where}{exc.strerror or exc}\n")
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
