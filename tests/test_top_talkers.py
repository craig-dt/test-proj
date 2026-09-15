"""Slice 1 acceptance: top-talkers src/dst, Table and JSON output, exit codes, stdin."""

from __future__ import annotations

import subprocess
import sys

from conftest import ANSI, HEADER


def rows_of(table: str) -> list[list[str]]:
    """Split a Table output into whitespace-separated cells, skipping the header line."""
    lines = [ln for ln in table.splitlines() if ln.strip()]
    return [ln.split() for ln in lines[1:]]


def test_limit_two_heaviest_by_bytes(run, twelve):
    r = run("top-talkers", str(twelve), "--limit", "2")
    assert r.code == 0
    body = rows_of(r.out)
    assert [row[0] for row in body] == ["10.0.0.1", "10.0.0.2"]


def test_by_flows_ranks_by_flow_count_and_keeps_other_columns(run, twelve):
    r = run("top-talkers", str(twelve), "--by", "flows", "--json")
    hosts = [x["host"] for x in r.json()["results"]]
    assert hosts == ["10.0.0.3", "10.0.0.2", "10.0.0.1"]
    first = r.json()["results"][0]
    assert first["flows"] == 5 and first["bytes"] == 900 and first["packets"] == 10


def test_direction_dst_ranks_destinations(run, twelve):
    r = run("top-talkers", str(twelve), "--direction", "dst", "--json")
    top = r.json()["results"][0]
    # 203.0.113.9 receives 2000+2000+750+750 = 5500 bytes.
    assert top["host"] == "203.0.113.9" and top["bytes"] == 5500


def test_ties_break_by_lower_ip_first(run, csv_file):
    text = HEADER + (
        "2026-09-14T18:00:00Z,10.0.0.9,203.0.113.9,443,tcp,100,1\n"
        "2026-09-14T18:00:01Z,10.0.0.2,203.0.113.9,443,tcp,100,1\n"
        "2026-09-14T18:00:02Z,10.0.0.10,203.0.113.9,443,tcp,100,1\n"
    )
    r = run("top-talkers", str(csv_file(text)), "--json")
    assert [x["host"] for x in r.json()["results"]] == ["10.0.0.2", "10.0.0.9", "10.0.0.10"]


def test_limit_zero_and_negative_are_usage_errors(run, twelve):
    for bad in ("0", "-1"):
        r = run("top-talkers", str(twelve), "--limit", bad)
        assert r.code == 1
        assert r.out == ""


def test_dirty_file_completes_and_reports_skipped(run, dirty):
    r = run("top-talkers", str(dirty))
    assert r.code == 0
    assert "3 rows skipped" in r.err
    assert rows_of(r.out)  # some output


def test_json_mode_is_one_object_with_meta(run, dirty):
    r = run("top-talkers", str(dirty), "--json")
    assert r.code == 0
    doc = r.json()  # parses; nothing else on stdout
    assert r.out.strip().startswith("{") and r.out.strip().endswith("}")
    assert doc["meta"]["rows_skipped"] == 3
    assert doc["meta"]["rows"] == 9
    assert doc["meta"]["command"] == "top-talkers"
    assert doc["meta"]["input"].endswith("dirty.csv")
    assert isinstance(doc["meta"]["elapsed_s"], float)
    assert isinstance(doc["meta"]["version"], str) and doc["meta"]["version"]
    assert "3 rows skipped" in r.err


def test_stdin_matches_path(run, twelve):
    from_path = run("top-talkers", str(twelve))
    from_stdin = run("top-talkers", "-", stdin_text=twelve.read_text())
    assert from_stdin.code == 0
    assert from_stdin.out == from_path.out


def test_table_is_plain_ascii(run, twelve):
    r = run("top-talkers", str(twelve))
    assert not ANSI.search(r.out)
    assert r.out.isascii()


def test_table_shows_human_bytes(run, csv_file):
    text = HEADER + "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,tcp,1200000000,1\n"
    r = run("top-talkers", str(csv_file(text)))
    assert "1.2 GB" in r.out


def test_bad_header_exits_2_with_one_line(run, csv_file):
    r = run("top-talkers", str(csv_file("time,src,dst\n1,2,3\n")))
    assert r.code == 2
    assert r.out == ""
    assert len(r.err.strip().splitlines()) == 1
    assert "Traceback" not in r.err


def test_missing_file_exits_2(run, tmp_path):
    r = run("top-talkers", str(tmp_path / "nope.csv"))
    assert r.code == 2 and "Traceback" not in r.err


def test_completely_empty_file_exits_2(run, csv_file):
    r = run("top-talkers", str(csv_file("")))
    assert r.code == 2


def test_header_only_file_exits_0_with_empty_results(run, csv_file):
    r = run("top-talkers", str(csv_file(HEADER)), "--json")
    assert r.code == 0
    assert r.json()["results"] == []


def test_bom_and_padded_header_are_accepted(run, csv_file):
    text = "﻿ ts, src_ip ,dst_ip,dst_port,proto,bytes,packets\r\n2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,tcp,1,1\r\n"
    r = run("top-talkers", str(csv_file(text)), "--json")
    assert r.code == 0
    assert r.json()["results"][0]["host"] == "10.0.0.1"


def test_undecodable_byte_does_not_traceback(run, csv_file):
    raw = HEADER.encode() + b"2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,tcp,1,1\n" + b"\xff\xfe,garbage\n"
    r = run("top-talkers", str(csv_file(raw, name="bad.csv", mode="wb")))
    assert r.code == 0 and "Traceback" not in r.err


def test_bad_header_message_is_sanitised(run, csv_file):
    r = run("top-talkers", str(csv_file("\x1b[31mevil\x1b[0m,x\n")))
    assert r.code == 2
    assert "\x1b" not in r.err


def test_usage_error_exit_1(run):
    r = run("top-talkers")  # missing file
    assert r.code == 1


def test_version_flag_via_installed_script():
    out = subprocess.run(["uv", "run", "flowtest", "--version"], capture_output=True, text=True, check=True)
    assert out.stdout.strip().startswith("flowtest 0.")
    assert sys.version_info >= (3, 12)
