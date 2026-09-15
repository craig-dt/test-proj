"""Final verify pass (v0.1): pins for gaps the whole-project review found in the tracked suite."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import HEADER

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "gen_flows.py"


@pytest.mark.parametrize("command", ["top-talkers", "top-ports", "beacons"])
def test_non_ascii_digits_in_limit_are_a_usage_error(run, twelve, command):
    r = run(command, str(twelve), "--limit", "٣")  # Arabic-Indic three
    assert r.code == 1 and r.out == ""


def test_min_flows_follows_the_same_digit_rule(run, twelve):
    assert run("beacons", str(twelve), "--min-flows", "٣").code == 1


@pytest.mark.parametrize("command", ["top-talkers", "top-ports"])
def test_single_pass_commands_never_mention_order(run, csv_file, command):
    # US-10 AC3: only beacons checks order; a shuffled file is silently fine for the others.
    text = HEADER + (
        "2026-09-14T18:00:05Z,10.0.0.1,203.0.113.9,443,tcp,1,1\n"
        "2026-09-14T18:00:01Z,10.0.0.1,203.0.113.9,443,tcp,1,1\n"
        "2026-09-14T17:00:00Z,10.0.0.1,203.0.113.9,443,tcp,1,1\n"
    )
    r = run(command, str(csv_file(text)))
    assert r.code == 0 and "out of order" not in r.err


def test_beacons_table_completes_on_a_dirty_file(run, dirty):
    r = run("beacons", str(dirty))
    assert r.code == 0 and "3 rows skipped" in r.err


@pytest.mark.parametrize("command", ["top-ports", "beacons"])
def test_undecodable_byte_does_not_traceback_in_every_command(run, csv_file, command):
    raw = HEADER.encode() + b"2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,tcp,1,1\n" + b"\xff\xfe,garbage\n"
    r = run(command, str(csv_file(raw, name="bad.csv", mode="wb")))
    assert r.code == 0 and "Traceback" not in r.err


def test_top_ports_json_uses_dst_port_like_beacons_and_the_csv_header(run, twelve):
    ports = run("top-ports", str(twelve), "--json").json()["results"]
    assert ports and all("dst_port" in x and "port" not in x for x in ports)


def test_generated_planted_beacons_rank_in_the_top_five(tmp_path):
    """PRD 11 success metric, automated: generate a 100 k-row file and check the sidecar Tuples are exactly
    the top 5 of `beacons` (the NTP-like Tuple is pushed below them by prevalence)."""
    out, side = tmp_path / "synth.csv", tmp_path / "synth.jsonl"
    subprocess.run(
        [sys.executable, str(SCRIPT), "--rows", "100000", "--seed", "11", "--output", str(out), "--beacons-out", str(side)],
        check=True,
        capture_output=True,
    )  # fmt: skip
    import io
    from contextlib import redirect_stderr, redirect_stdout

    from flowtest.cli import main

    buf, err = io.StringIO(), io.StringIO()
    with redirect_stdout(buf), redirect_stderr(err):
        code = main(["beacons", str(out), "--json", "--limit", "5"])
    assert code == 0
    top5 = {
        (x["src_ip"], x["dst_ip"], x["dst_port"], x["proto"]) for x in json.loads(buf.getvalue())["results"]
    }
    planted = {
        (b["src_ip"], b["dst_ip"], b["dst_port"], b["proto"])
        for b in (json.loads(line) for line in side.read_text().splitlines() if line.strip())
    }
    assert top5 == planted
