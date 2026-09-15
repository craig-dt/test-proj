"""Slice 4 acceptance (PRD 6.5, US-11): colour only on a TTY, plain when piped, --no-color and NO_COLOR.

The TTY cases run the CLI as a subprocess with stdout attached to a pseudo-terminal, so the decision is
made by the real isatty() check rather than a mock.
"""

from __future__ import annotations

import os
import select
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import pytest
from conftest import ANSI, HEADER

pty = pytest.importorskip("pty")  # POSIX only; Windows is nice-to-have per PRD 6.6

TTY_DEADLINE_S = 20.0


@dataclass
class Captured:
    code: int
    out: str
    err: str


def _env(**overrides: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k != "NO_COLOR"}
    env.update(overrides)
    return env


def run_piped(*argv: str, **env: str) -> Captured:
    proc = subprocess.run(
        [sys.executable, "-m", "flowtest.cli", *argv],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        env=_env(**env),
        check=False,
    )
    return Captured(proc.returncode, proc.stdout, proc.stderr)


def run_tty(*argv: str, stderr_on_tty: bool = False, **env: str) -> Captured:
    """Run the CLI with stdout on a pseudo-terminal.

    stderr is a plain pipe by default (drained on a thread so it can never deadlock); with
    ``stderr_on_tty`` it shares the pseudo-terminal, which is how a real terminal session looks.
    Every read has a deadline and the child is killed on expiry, so a hang fails fast instead of
    stalling CI.
    """
    master, slave = pty.openpty()
    proc = subprocess.Popen(
        [sys.executable, "-m", "flowtest.cli", *argv],
        stdin=subprocess.DEVNULL,
        stdout=slave,
        stderr=slave if stderr_on_tty else subprocess.PIPE,
        env=_env(**env),
    )
    os.close(slave)

    err_chunks: list[bytes] = []
    drain: threading.Thread | None = None
    if proc.stderr is not None:
        drain = threading.Thread(target=lambda: err_chunks.append(proc.stderr.read()), daemon=True)
        drain.start()

    chunks: list[bytes] = []
    deadline = time.monotonic() + TTY_DEADLINE_S
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                proc.kill()
                raise TimeoutError(f"CLI produced no EOF on the pty within {TTY_DEADLINE_S}s")
            ready, _, _ = select.select([master], [], [], remaining)
            if not ready:
                continue
            try:
                data = os.read(master, 65536)
            except OSError:  # EIO once the child has closed its end
                break
            if not data:
                break
            chunks.append(data)
    finally:
        os.close(master)
        try:
            proc.wait(timeout=TTY_DEADLINE_S)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        if drain is not None:
            drain.join(timeout=TTY_DEADLINE_S)
    # The terminal driver turns "\n" into "\r\n" on output; undo that so lines compare to piped output.
    out = b"".join(chunks).decode("utf-8").replace("\r\n", "\n")
    err = b"".join(err_chunks).decode("utf-8")
    return Captured(proc.returncode, out, err)


def strip_ansi(text: str) -> str:
    import re

    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def test_piped_table_has_no_escape_sequences(twelve: Path):
    r = run_piped("top-talkers", str(twelve))
    assert r.code == 0
    assert not ANSI.search(r.out)


def test_tty_colours_header_and_first_result_only_and_keeps_content(twelve: Path):
    tty = run_tty("top-talkers", str(twelve))
    plain = run_piped("top-talkers", str(twelve))
    assert tty.code == 0 and plain.code == 0

    lines = tty.out.splitlines()
    assert len(lines) == 4  # header + three hosts
    assert ANSI.search(lines[0]), "header should carry an escape sequence"
    assert ANSI.search(lines[1]), "first result should carry an escape sequence"
    assert not ANSI.search(lines[2]) and not ANSI.search(lines[3]), "other rows stay plain"

    assert strip_ansi(tty.out) == plain.out


def test_stderr_is_never_coloured_even_on_a_tty(twelve: Path):
    # stderr shares the pseudo-terminal here, so a coloured summary line would show up in the capture.
    tty = run_tty("top-talkers", str(twelve), stderr_on_tty=True)
    assert tty.code == 0
    merged_lines = tty.out.splitlines()
    summary = [ln for ln in merged_lines if ln.endswith("rows skipped")]
    assert summary == ["0 rows skipped"], "summary line must be present and plain"
    coloured = [ln for ln in merged_lines if ANSI.search(ln)]
    assert len(coloured) == 2, "only the header and the first result carry escapes"


def test_every_command_honours_no_color_on_a_tty(twelve: Path):
    # Guards the shared-renderer promise: each registered command must pass --no-color through.
    from flowtest.commands import COMMANDS

    for module in COMMANDS:
        r = run_tty(module.NAME, str(twelve), "--no-color")
        assert r.code == 0, f"{module.NAME} failed under --no-color: {r.err}"
        assert not ANSI.search(r.out), f"{module.NAME} coloured a TTY despite --no-color"


def test_no_color_flag_on_tty_is_plain(twelve: Path):
    r = run_tty("top-talkers", str(twelve), "--no-color")
    assert r.code == 0
    assert not ANSI.search(r.out)
    assert r.out == run_piped("top-talkers", str(twelve)).out


def test_no_color_env_on_tty_is_plain(twelve: Path):
    r = run_tty("top-talkers", str(twelve), NO_COLOR="1")
    assert r.code == 0
    assert not ANSI.search(r.out)


def test_no_color_env_any_non_empty_value_counts(twelve: Path):
    r = run_tty("top-talkers", str(twelve), NO_COLOR="false")
    assert not ANSI.search(r.out)


def test_empty_no_color_env_does_not_disable_colour(twelve: Path):
    # The no-color.org convention: only a non-empty value counts.
    r = run_tty("top-talkers", str(twelve), NO_COLOR="")
    assert ANSI.search(r.out)


def test_json_on_tty_never_coloured(twelve: Path):
    import json

    r = run_tty("top-talkers", str(twelve), "--json")
    assert r.code == 0
    assert not ANSI.search(r.out)
    doc = json.loads(r.out)
    assert doc["results"][0]["host"] == "10.0.0.1"


def test_header_only_file_on_tty_colours_the_header_without_a_first_row(csv_file):
    r = run_tty("top-talkers", str(csv_file(HEADER)))
    assert r.code == 0
    lines = r.out.splitlines()
    assert len(lines) == 1
    assert ANSI.search(lines[0])
    assert strip_ansi(lines[0]) == "host  bytes  packets  flows"


def test_help_documents_no_color_and_the_env_var(run):
    top = run("--help")
    assert top.code == 0
    assert "--no-color" in top.out and "NO_COLOR" in top.out

    sub = run("top-talkers", "--help")
    assert sub.code == 0
    assert "--no-color" in sub.out and "NO_COLOR" in sub.out


def test_no_color_flag_is_accepted_when_piped(run, twelve: Path):
    # The flag is harmless where colour was never going to be used.
    r = run("top-talkers", str(twelve), "--no-color")
    assert r.code == 0
    assert not ANSI.search(r.out)
