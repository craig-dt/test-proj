"""Shared fixtures: small CSV files written to tmp_path, and a CLI runner."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

import pytest

HEADER = "ts,src_ip,dst_ip,dst_port,proto,bytes,packets\n"

# 12 rows, three source hosts. Bytes: 10.0.0.1 = 6000, 10.0.0.2 = 3000, 10.0.0.3 = 900.
# Flows:  10.0.0.1 = 3,    10.0.0.2 = 4,    10.0.0.3 = 5.
TWELVE_ROWS = HEADER + (
    "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,tcp,2000,10\n"
    "2026-09-14T18:00:01Z,10.0.0.1,203.0.113.9,443,tcp,2000,10\n"
    "2026-09-14T18:00:02Z,10.0.0.1,203.0.113.10,443,tcp,2000,10\n"
    "2026-09-14T18:00:03Z,10.0.0.2,203.0.113.9,443,tcp,750,5\n"
    "2026-09-14T18:00:04Z,10.0.0.2,203.0.113.9,443,tcp,750,5\n"
    "2026-09-14T18:00:05Z,10.0.0.2,203.0.113.11,53,udp,750,5\n"
    "2026-09-14T18:00:06Z,10.0.0.2,203.0.113.11,53,udp,750,5\n"
    "2026-09-14T18:00:07Z,10.0.0.3,203.0.113.12,80,tcp,180,2\n"
    "2026-09-14T18:00:08Z,10.0.0.3,203.0.113.12,80,tcp,180,2\n"
    "2026-09-14T18:00:09Z,10.0.0.3,203.0.113.12,80,tcp,180,2\n"
    "2026-09-14T18:00:10Z,10.0.0.3,203.0.113.13,80,tcp,180,2\n"
    "2026-09-14T18:00:11Z,10.0.0.3,203.0.113.13,,icmp,180,2\n"
)

# Three malformed rows (bad ts, bad ip, negative bytes) among six valid ones; row 7 is epoch + upper-case proto.
DIRTY_ROWS = HEADER + (
    "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,tcp,100,1\n"
    "not-a-timestamp,10.0.0.1,203.0.113.9,443,tcp,100,1\n"
    "2026-09-14T18:00:02Z,10.0.0.1,203.0.113.9,443,tcp,100,1\n"
    "2026-09-14T18:00:03Z,300.0.0.1,203.0.113.9,443,tcp,100,1\n"
    "2026-09-14T18:00:04Z,10.0.0.1,203.0.113.9,443,tcp,-5,1\n"
    "2026-09-14T18:00:05Z,10.0.0.1,203.0.113.9,443,tcp,100,1\n"
    "1757873000,10.0.0.2,203.0.113.9,443,TCP,100,1\n"
    "2026-09-14T18:00:07Z,10.0.0.2,203.0.113.9,443,tcp,100,1\n"
    "2026-09-14T18:00:08Z,10.0.0.2,203.0.113.9,443,tcp,100,1\n"
)

ANSI = re.compile(r"\x1b\[")


@dataclass
class Result:
    code: int
    out: str
    err: str

    def json(self) -> dict:
        return json.loads(self.out)


@pytest.fixture
def csv_file(tmp_path: Path):
    """Write text to a temp CSV and return its path."""

    def _write(text: str, name: str = "flows.csv", mode: str = "w", encoding: str = "utf-8") -> Path:
        p = tmp_path / name
        if mode == "wb":
            p.write_bytes(text if isinstance(text, bytes) else text.encode(encoding))
        else:
            p.write_text(text, encoding=encoding, newline="")
        return p

    return _write


@pytest.fixture
def twelve(csv_file) -> Path:
    return csv_file(TWELVE_ROWS)


@pytest.fixture
def dirty(csv_file) -> Path:
    return csv_file(DIRTY_ROWS, name="dirty.csv")


@pytest.fixture
def run(capsys):
    """Run the CLI in-process through its public entry point and capture the outcome."""
    from flowtest.cli import main

    def _run(*argv: str, stdin_text: str | None = None) -> Result:
        import io
        import sys

        old_stdin = sys.stdin
        try:
            if stdin_text is not None:
                sys.stdin = io.TextIOWrapper(io.BytesIO(stdin_text.encode("utf-8")), encoding="utf-8")
            try:
                code = main(list(argv))
            except SystemExit as e:  # argparse paths
                code = int(e.code or 0)
        finally:
            sys.stdin = old_stdin
        captured = capsys.readouterr()
        return Result(code=code, out=captured.out, err=captured.err)

    return _run
