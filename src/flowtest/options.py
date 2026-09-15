"""Argument helpers shared by the commands: common options, validated types, run metadata."""

from __future__ import annotations

import argparse
import time
from importlib import metadata
from typing import Any

from flowtest.reader import ReadStats


def tool_version() -> str:
    try:
        return metadata.version("flowtest")
    except metadata.PackageNotFoundError:  # running from a bare checkout
        return "0.0.0+unknown"


def positive_int(raw: str) -> int:
    """A positive integer written in plain ASCII digits (the same rule the CSV fields follow)."""
    if not (raw.isascii() and raw.isdigit()):
        raise argparse.ArgumentTypeError(f"{raw!r} is not a positive integer")
    value = int(raw)
    if value <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return value


def add_common(parser: argparse.ArgumentParser, *, allow_stdin: bool = True) -> None:
    """The options every command shares: the input, --limit, --json and --no-color."""
    file_help = "CSV path" + (", or - for stdin" if allow_stdin else "")
    parser.add_argument("file", help=file_help)
    parser.add_argument(
        "--limit", type=positive_int, default=20, metavar="N", help="rows to show (default 20)"
    )
    parser.add_argument("--json", action="store_true", help="emit one JSON object instead of a table")
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="plain table even on a terminal (a non-empty NO_COLOR environment variable does the same)",
    )


def build_meta(command: str, source: str, stats: ReadStats, start: float) -> dict[str, Any]:
    return {
        "command": command,
        "input": source,
        "rows": stats.rows,
        "rows_skipped": stats.skipped,
        "elapsed_s": round(time.perf_counter() - start, 3),
        "version": tool_version(),
    }
