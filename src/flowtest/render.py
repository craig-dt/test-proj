"""Table and JSON rendering shared by every command (PRD 6.5).

Table output: header row, aligned ASCII columns, right-aligned numbers, human units for bytes.
JSON output: exactly one object on stdout, raw numbers, nothing else.
Colour is added by a later slice; this module emits plain text only.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import IO, Any

from flowtest.reader import ReadStats, sanitize

_UNITS = ("B", "KB", "MB", "GB", "TB", "PB")


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


def render_table(columns: list[Column], rows: list[dict[str, Any]]) -> str:
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

    out = [line_of([c.header for c in columns])]
    out.extend(line_of(line) for line in cells)
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
    out: IO[str] | None = None,
    err: IO[str] | None = None,
) -> None:
    """Write the command's output to stdout and the skipped-row summary to stderr."""
    out = out or sys.stdout
    err = err or sys.stderr
    out.write(render_json(results, meta) if as_json else render_table(columns, results))
    err.write(f"{stats.skipped} rows skipped\n")
