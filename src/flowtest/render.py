"""Table and JSON rendering shared by every command (PRD 6.5).

Table output: header row, aligned ASCII columns, right-aligned numbers, human units for bytes.
JSON output: exactly one object on stdout, raw numbers, nothing else.

Colour (US-11): only when stdout is a TTY and neither --no-color nor a non-empty NO_COLOR is set. The header
is bold and the first result is highlighted (reverse video); every other byte is identical to the plain
rendering. Colour never carries meaning on its own, and JSON output is never coloured.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import IO, Any

from flowtest.reader import ReadStats, sanitize

_UNITS = ("B", "KB", "MB", "GB", "TB", "PB")

BOLD = "\x1b[1m"
HIGHLIGHT = "\x1b[7m"
RESET = "\x1b[0m"


def use_color(*, no_color: bool, out: IO[str]) -> bool:
    """--no-color wins, then a non-empty NO_COLOR (no-color.org), then the TTY check."""
    if no_color or os.environ.get("NO_COLOR"):
        return False
    isatty = getattr(out, "isatty", None)
    return bool(isatty and isatty())


def human_bytes(n: int) -> str:
    """1000-based units with one decimal above bytes: 1200000000 -> '1.2 GB', 999999 -> '1.0 MB'."""
    if n < 1000:
        return f"{n} B"
    value = float(n)
    for unit in _UNITS[1:]:
        value /= 1000
        if round(value, 1) < 1000 or unit == _UNITS[-1]:
            return f"{value:.1f} {unit}"
    return f"{n} B"  # unreachable, keeps type checkers calm


def fmt_int(n: int) -> str:
    return str(n)


@dataclass(frozen=True)
class Column:
    header: str
    key: str
    align: str = "l"  # 'l' or 'r'
    fmt: Callable[[Any], str] = str


def render_table(columns: list[Column], rows: list[dict[str, Any]], *, color: bool = False) -> str:
    # Every cell passes through sanitize(): nothing from the CSV reaches the terminal unsanitised,
    # whatever the parser accepted.
    cells = [[sanitize(col.fmt(row[col.key])) for col in columns] for row in rows]
    widths = [len(col.header) for col in columns]
    for line in cells:
        for i, text in enumerate(line):
            widths[i] = max(widths[i], len(text))

    def line_of(values: list[str]) -> str:
        parts = []
        for col, width, text in zip(columns, widths, values, strict=True):
            parts.append(text.rjust(width) if col.align == "r" else text.ljust(width))
        return "  ".join(parts).rstrip()

    def styled(line: str, style: str) -> str:
        # Wrap the whole line, after padding, so stripping the codes gives back the plain line exactly.
        return f"{style}{line}{RESET}" if color else line

    out = [styled(line_of([c.header for c in columns]), BOLD)]
    for i, line in enumerate(cells):
        out.append(styled(line_of(line), HIGHLIGHT) if i == 0 else line_of(line))
    return "\n".join(out) + "\n"


def render_json(results: list[dict[str, Any]], meta: dict[str, Any]) -> str:
    return json.dumps({"results": results, "meta": meta}) + "\n"


def emit(
    *,
    as_json: bool,
    columns: list[Column],
    results: list[dict[str, Any]],
    meta: dict[str, Any],
    stats: ReadStats,
    no_color: bool,  # required on purpose: a command that forgets it fails its first test, not the analyst
    out: IO[str] | None = None,
    err: IO[str] | None = None,
) -> None:
    """Write the command's output to stdout and the skipped-row summary to stderr."""
    out = out or sys.stdout
    err = err or sys.stderr
    if as_json:
        out.write(render_json(results, meta))
    else:
        out.write(render_table(columns, results, color=use_color(no_color=no_color, out=out)))
    err.write(f"{stats.skipped} rows skipped\n")
