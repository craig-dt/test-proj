"""Streaming Flow reader shared by every command (PRD 6.1).

One Flow at a time, never the whole file. Rows that violate the contract are Skipped rows: counted,
never fatal. Only a missing/unreadable file, an empty file or a bad header is fatal (InputError, exit 2).
"""

from __future__ import annotations

import csv
import io
import ipaddress
import math
import re
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from typing import IO, NamedTuple

EXPECTED_HEADER = ("ts", "src_ip", "dst_ip", "dst_port", "proto", "bytes", "packets")
TS_MIN = 946_684_800  # 2000-01-01T00:00:00Z
TS_MAX = 4_102_444_800  # 2100-01-01T00:00:00Z (exclusive)
PROTOS = frozenset({"tcp", "udp", "icmp"})
ECHO_LIMIT = 80
# Only plain ASCII digits count as numbers: no sign, underscore, exponent or Unicode digits. At most 20
# digits: far beyond any real counter, and it keeps int() away from Python's 4300-digit ValueError.
_DIGITS = re.compile(r"[0-9]{1,20}")
_EPOCH = re.compile(r"[0-9]{1,20}(?:\.[0-9]+)?")


def clean_field(raw: str) -> str:
    """Trim whitespace and one pair of surrounding quotes. Quoting is disabled in the CSV reader
    (a stray quote must cost one row, not the rest of the file), so fully-quoted exports are
    handled here instead."""
    s = raw.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1].strip()
    return s


class InputError(Exception):
    """The input could not be read at all. The CLI maps this to exit code 2."""


class Flow(NamedTuple):
    ts: int
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str
    bytes: int
    packets: int


@dataclass
class ReadStats:
    rows: int = 0
    skipped: int = 0
    first_skipped_line: int | None = None


def sanitize(text: str, limit: int = ECHO_LIMIT) -> str:
    """Make untrusted input text safe to echo: strip control characters, truncate."""
    clean = "".join(ch for ch in text if ch.isprintable())
    return clean if len(clean) <= limit else clean[:limit] + "..."


@lru_cache(maxsize=1 << 16)
def parse_ts(raw: str) -> int | None:
    """Epoch seconds (optionally fractional) or ISO-8601 -> whole UTC seconds; None if invalid."""
    s = clean_field(raw)
    if not s:
        return None
    if _EPOCH.fullmatch(s):
        value = float(s)
    else:
        if s[-1] in "Zz":
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        value = dt.timestamp()
    if not math.isfinite(value):
        return None
    ts = int(value)
    return ts if TS_MIN <= ts < TS_MAX else None


@lru_cache(maxsize=1 << 16)
def parse_ip(raw: str) -> str | None:
    """Canonical string form of an IPv4/IPv6 address, or None.

    Scoped IPv6 literals (``fe80::1%eth0``) are rejected: flow exports never carry zone ids and
    ``ipaddress`` echoes the scope text verbatim, which would let a crafted CSV put terminal escape
    sequences into the output. IPv4-mapped IPv6 (``::ffff:10.0.0.1``) is unwrapped to the IPv4 host.
    """
    s = clean_field(raw)
    if "%" in s:
        return None
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


@lru_cache(maxsize=1 << 16)
def ip_sort_key(addr: str) -> tuple[int, int]:
    """Sort key giving IP address order (IPv4 before IPv6, then numeric)."""
    ip = ipaddress.ip_address(addr)
    return (ip.version, int(ip))


def _non_negative_int(raw: str) -> int | None:
    s = clean_field(raw)
    return int(s) if _DIGITS.fullmatch(s) else None


def parse_row(fields: list[str]) -> Flow | None:
    """Apply the column contract to one CSV record. None means Skipped row."""
    if len(fields) != 7:
        return None
    ts = parse_ts(fields[0])
    src = parse_ip(fields[1])
    dst = parse_ip(fields[2])
    proto = clean_field(fields[4]).lower()
    if ts is None or src is None or dst is None or proto not in PROTOS:
        return None
    if proto == "icmp":
        port = 0  # ICMP has no port; the glossary says ICMP Tuples use port 0 whatever the export says
    else:
        port = _non_negative_int(fields[3])
        if port is None or port > 65535:
            return None
    nbytes = _non_negative_int(fields[5])
    packets = _non_negative_int(fields[6])
    if nbytes is None or packets is None:
        return None
    return Flow(ts, src, dst, port, proto, nbytes, packets)


class FlowStream:
    """Iterates Flows from an open text handle, collecting ReadStats as it goes."""

    def __init__(self, handle: IO[str], source: str) -> None:
        # QUOTE_NONE: a lone quote must cost one row, never swallow the rest of the file (review F1).
        # Fully-quoted exports still work because clean_field() strips one pair of quotes per field.
        self._reader = csv.reader(handle, quoting=csv.QUOTE_NONE)
        self.source = source
        self.stats = ReadStats()

    def check_header(self) -> None:
        try:
            first = next(self._reader)
        except StopIteration:
            raise InputError(f"{self.source}: empty input, no header row") from None
        except csv.Error as exc:
            raise InputError(f"{self.source}: cannot parse header ({exc})") from None
        cells = tuple(clean_field(c) for c in first)  # BOM already removed by utf-8-sig
        if cells != EXPECTED_HEADER:
            found = sanitize(",".join(first))
            raise InputError(
                f"{self.source}: unexpected header {found!r}; expected {','.join(EXPECTED_HEADER)}"
            )

    def _skip(self, line: int) -> None:
        self.stats.skipped += 1
        if self.stats.first_skipped_line is None:
            self.stats.first_skipped_line = line

    def __iter__(self) -> Iterator[Flow]:
        reader = self._reader
        stats = self.stats
        while True:
            start_line = reader.line_num + 1
            try:
                fields = next(reader)
            except StopIteration:
                return
            except csv.Error:
                stats.rows += 1
                self._skip(start_line)
                continue
            if not fields:
                continue  # blank line: not a row
            stats.rows += 1
            flow = parse_row(fields)
            if flow is None:
                self._skip(start_line)
                continue
            yield flow


@contextmanager
def read_flows(source: str) -> Iterator[FlowStream]:
    """Open a path (or '-' for stdin), validate the header, and yield a FlowStream."""
    if source == "-":
        handle: IO[str] = io.TextIOWrapper(
            sys.stdin.buffer, encoding="utf-8-sig", errors="replace", newline=""
        )
        owns = False
    else:
        try:
            handle = open(source, encoding="utf-8-sig", errors="replace", newline="")  # noqa: SIM115
        except OSError as exc:
            raise InputError(f"cannot read {source}: {exc.strerror or exc}") from None
        owns = True
    try:
        stream = FlowStream(handle, source)
        stream.check_header()
        yield stream
    finally:
        if owns:
            handle.close()
        else:
            handle.detach()
