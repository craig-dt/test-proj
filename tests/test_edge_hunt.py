"""Edge-case hunt across the whole CLI (PRD 6.1-6.5, US-01..US-12): behaviour the slice tests do not pin.

Everything runs through the public CLI via the `run` fixture. Fixtures are built in-test from HEADER.

Probes removed because they FAILED (PRD silence, not defects; see the hunt report):
- "a blank line between data rows is one Skipped row": observed rows_skipped == 0 and meta.rows == 2.
  The reader treats an empty line as no row at all. PRD 6.1 never mentions blank lines. Replaced below by
  a pin of the observed behaviour (test_blank_line_is_neither_a_row_nor_a_skipped_row).
- "--limit with a non-ASCII digit (Arabic-Indic three) is a usage error": observed exit 0 with limit 3.
  PRD 6.1's plain-ASCII-digits rule is scoped to CSV fields; 6.2/6.3 only say --limit "must be a positive
  integer". Dropped from the --limit parametrize.
"""

from __future__ import annotations

import csv
import json

import pytest
from conftest import ANSI, HEADER, rows_of

COMMANDS = ("top-talkers", "top-ports", "beacons")
SHARED_META = {"command", "input", "rows", "rows_skipped", "elapsed_s", "version"}

START = 1_789_344_000  # 2026-09-14T00:00:00Z
GOOD = "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,tcp,100,1\n"
BAD_THREE = (
    "not-a-timestamp,10.0.0.1,203.0.113.9,443,tcp,100,1\n"
    "2026-09-14T18:00:03Z,300.0.0.1,203.0.113.9,443,tcp,100,1\n"
    "2026-09-14T18:00:04Z,10.0.0.1,203.0.113.9,443,tcp,-5,1\n"
)


def row(ts: int, src: str, dst: str, port, proto: str, size: int = 1000, packets: int = 2) -> str:
    return f"{ts},{src},{dst},{port},{proto},{size},{packets}\n"


def regular(src, dst, port, proto, *, start=START, count=24, interval=3600, size=1000) -> list[str]:
    return [row(start + i * interval, src, dst, port, proto, size) for i in range(count)]


def tuple_of(x: dict) -> tuple:
    return (x["src_ip"], x["dst_ip"], x["dst_port"], x["proto"])


# ---------------------------------------------------------------- 6.1 ingestion: skipped rows


@pytest.mark.parametrize("command", COMMANDS)
def test_only_malformed_rows_is_a_success_with_three_skipped_and_empty_results(run, csv_file, command):
    path = csv_file(HEADER + BAD_THREE)
    r = run(command, str(path), "--json")
    assert r.code == 0
    doc = r.json()
    assert doc["results"] == []
    assert doc["meta"]["rows"] == 3 and doc["meta"]["rows_skipped"] == 3
    assert "3 rows skipped" in r.err
    table = run(command, str(path))
    assert table.code == 0 and rows_of(table.out) == []


@pytest.mark.parametrize(
    "line",
    [
        ",10.0.0.1,203.0.113.9,443,tcp,100,1\n",  # empty ts
        "2026-09-14T18:00:00Z,,203.0.113.9,443,tcp,100,1\n",  # empty src_ip
        "2026-09-14T18:00:00Z,10.0.0.1,,443,tcp,100,1\n",  # empty dst_ip
        "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,,100,1\n",  # empty proto
        "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,tcp,,1\n",  # empty bytes
        "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,tcp,100,\n",  # empty packets
        "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,udp,100,1,extra\n",  # 8 fields
        "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,tcp,100\n",  # 6 fields
        ",,,,,,\n",  # 7 empty fields
    ],
)
def test_seven_fields_with_a_required_one_empty_or_wrong_arity_is_one_skipped_row(run, csv_file, line):
    doc = run("top-talkers", str(csv_file(HEADER + GOOD + line + GOOD)), "--json").json()
    assert doc["meta"]["rows_skipped"] == 1
    assert doc["results"][0]["flows"] == 2


@pytest.mark.parametrize("command", COMMANDS)
def test_blank_line_is_neither_a_row_nor_a_skipped_row(run, csv_file, command):
    # PRD 6.1 is silent on blank lines; the CLI ignores them entirely (not counted in rows or rows_skipped).
    doc = run(command, str(csv_file(HEADER + GOOD + "\n" + GOOD + "\n\n")), "--json").json()
    assert doc["meta"]["rows"] == 2 and doc["meta"]["rows_skipped"] == 0


def test_a_second_header_line_is_one_skipped_row(run, csv_file):
    doc = run("top-talkers", str(csv_file(HEADER + HEADER + GOOD)), "--json").json()
    assert doc["meta"]["rows"] == 2 and doc["meta"]["rows_skipped"] == 1
    assert doc["results"][0]["flows"] == 1


def test_crlf_throughout_gives_the_same_results_as_lf(run, csv_file):
    lf = HEADER + "".join(regular("10.0.0.5", "203.0.113.9", 443, "tcp")) + GOOD
    crlf = lf.replace("\n", "\r\n")
    for command in COMMANDS:
        a = run(command, str(csv_file(lf, name="lf.csv")), "--json").json()
        b = run(command, str(csv_file(crlf, name="crlf.csv")), "--json").json()
        assert a["results"] == b["results"], command
        assert b["meta"]["rows_skipped"] == 0 and b["meta"]["rows"] == 25


def test_trailing_line_without_newline_is_read(run, csv_file):
    doc = run("top-talkers", str(csv_file(HEADER + GOOD + GOOD.rstrip("\n"))), "--json").json()
    assert doc["meta"]["rows"] == 2 and doc["meta"]["rows_skipped"] == 0
    assert doc["results"][0]["flows"] == 2


# ---------------------------------------------------------------- 6.1 ingestion: header


@pytest.mark.parametrize(
    "header",
    [
        "TS,SRC_IP,DST_IP,DST_PORT,PROTO,BYTES,PACKETS\n",  # different case
        "ts,src_ip,dst_ip,dst_port,proto,bytes,packets,\n",  # trailing comma
        "ts,src_ip,dst_ip,dst_port,proto,bytes\n",  # missing column
        "src_ip,ts,dst_ip,dst_port,proto,bytes,packets\n",  # wrong order
        "ts;src_ip;dst_ip;dst_port;proto;bytes;packets\n",  # wrong delimiter
    ],
)
@pytest.mark.parametrize("command", COMMANDS)
def test_header_that_is_not_exactly_the_contract_exits_2_with_empty_stdout(run, csv_file, header, command):
    r = run(command, str(csv_file(header + GOOD)))
    assert r.code == 2 and r.out == ""
    assert "Traceback" not in r.err


@pytest.mark.parametrize("command", COMMANDS)
def test_bom_plus_fully_quoted_header_and_crlf_is_accepted(run, csv_file, command):
    text = '﻿"ts","src_ip","dst_ip","dst_port","proto","bytes","packets"\r\n' + GOOD.replace("\n", "\r\n")
    r = run(command, str(csv_file(text)), "--json")
    assert r.code == 0
    assert r.json()["meta"]["rows"] == 1 and r.json()["meta"]["rows_skipped"] == 0


def test_bom_only_file_is_an_empty_file_and_exits_2(run, csv_file):
    r = run("top-talkers", str(csv_file("﻿")))
    assert r.code == 2 and r.out == ""


def test_empty_stdin_exits_2_for_stdin_commands(run):
    for command in ("top-talkers", "top-ports"):
        r = run(command, "-", stdin_text="")
        assert r.code == 2 and r.out == "", command


# ---------------------------------------------------------------- 6.1 oversized record, both beacon passes


def test_200kb_field_before_valid_rows_is_one_skipped_row_in_both_beacon_passes(run, csv_file):
    assert 200_000 > csv.field_size_limit()
    huge = "x" * 200_000
    text = (
        HEADER
        + f"{huge},10.0.0.1,203.0.113.9,443,tcp,1,1\n"
        + "".join(regular("10.0.0.5", "203.0.113.9", 443, "tcp"))
    )
    r = run("beacons", str(csv_file(text)), "--json")
    assert r.code == 0
    doc = r.json()
    assert doc["meta"]["rows"] == 25 and doc["meta"]["rows_skipped"] == 1
    assert [tuple_of(x) for x in doc["results"]] == [("10.0.0.5", "203.0.113.9", 443, "tcp")]
    assert doc["results"][0]["flows"] == 24
    assert r.err.count("rows skipped") == 1, "the skipped-row summary prints once, not once per pass"
    assert "x" * 81 not in r.err, "echoed fragments are truncated to 80 characters"


# ---------------------------------------------------------------- 6.4 beacons: gate and span edge cases


def test_duplicate_identical_rows_count_as_flows_but_not_as_intervals(run, csv_file):
    lines = [ln for ln in regular("10.0.0.5", "203.0.113.9", 443, "tcp") for _ in range(2)]
    doc = run("beacons", str(csv_file(HEADER + "".join(lines))), "--json").json()
    assert doc["meta"]["rows_out_of_order"] == 0, "an equal timestamp is not earlier, so not out of order"
    [x] = doc["results"]
    assert x["flows"] == 48 and x["median_interval_s"] == 3600.0


def test_all_flows_internal_to_internal_gives_no_candidates_and_zero_internal_hosts(run, csv_file):
    path = csv_file(HEADER + "".join(regular("10.0.0.5", "192.168.1.9", 443, "tcp")))
    r = run("beacons", str(path), "--json")
    assert r.code == 0
    doc = r.json()
    assert doc["results"] == []
    assert doc["meta"]["rows"] == 24 and doc["meta"]["internal_hosts_total"] == 0
    assert doc["meta"]["prevalence_applied"] is False


def test_all_flows_internal_to_internal_notes_the_skipped_prevalence_adjustment_once(run, csv_file):
    # PRD 6.4: "below [10] no adjustment is made and stderr says so once". Zero hosts is below ten.
    path = csv_file(HEADER + "".join(regular("10.0.0.5", "192.168.1.9", 443, "tcp")))
    r = run("beacons", str(path))
    assert r.err.count("prevalence adjustment skipped") == 1


def test_min_flows_above_every_tuple_gives_empty_results_and_exit_0(run, csv_file):
    path = csv_file(HEADER + "".join(regular("10.0.0.5", "203.0.113.9", 443, "tcp", count=24)))
    r = run("beacons", str(path), "--json", "--min-flows", "25")
    assert r.code == 0 and r.json()["results"] == []
    assert r.json()["meta"]["internal_hosts_total"] == 1, "the host still counts even when nothing is scored"


def test_single_second_file_span_scores_nothing_and_exits_0(run, csv_file):
    lines = [row(START, f"10.0.0.{i}", "203.0.113.9", 443, "tcp") for i in range(1, 13)] * 2
    r = run("beacons", str(csv_file(HEADER + "".join(lines))), "--json", "--min-flows", "1")
    assert r.code == 0 and r.json()["results"] == []
    assert r.json()["meta"]["rows"] == 24


def test_tuple_with_one_non_zero_interval_is_absent_but_a_span_wide_neighbour_is_scored(run, csv_file):
    burst = [row(START, "10.0.0.7", "203.0.113.7", 443, "tcp") for _ in range(11)]
    burst.append(row(START + 3600, "10.0.0.7", "203.0.113.7", 443, "tcp"))
    good = regular("10.0.0.5", "203.0.113.9", 443, "tcp")
    doc = run("beacons", str(csv_file(HEADER + "".join(burst + good))), "--json").json()
    assert [tuple_of(x) for x in doc["results"]] == [("10.0.0.5", "203.0.113.9", 443, "tcp")]


def test_internal_everything_leaves_no_outbound_flows(run, csv_file):
    path = csv_file(HEADER + "".join(regular("10.0.0.5", "203.0.113.9", 443, "tcp")))
    r = run("beacons", str(path), "--json", "--internal", "0.0.0.0/0")
    assert r.code == 0 and r.json()["results"] == []
    assert r.json()["meta"]["internal_hosts_total"] == 0


def test_internal_ipv4_only_override_makes_ipv6_sources_external(run, csv_file):
    path = csv_file(
        HEADER
        + "".join(regular("fd00::5", "2001:db8::9", 443, "tcp"))
        + "".join(regular("10.0.0.5", "203.0.113.9", 443, "tcp"))
    )
    results = run("beacons", str(path), "--json", "--internal", "10.0.0.0/8").json()["results"]
    assert [x["src_ip"] for x in results] == ["10.0.0.5"]


def test_second_internal_value_invalid_is_a_usage_error_with_empty_stdout(run, csv_file):
    path = csv_file(HEADER + "".join(regular("10.0.0.5", "203.0.113.9", 443, "tcp")))
    r = run("beacons", str(path), "--internal", "10.0.0.0/8", "--internal", "10.0.0.0/33")
    assert r.code == 1 and r.out == ""
    assert "Traceback" not in r.err


def test_internal_host_address_without_prefix_is_a_single_host_network(run, csv_file):
    path = csv_file(
        HEADER
        + "".join(regular("10.0.0.5", "203.0.113.9", 443, "tcp"))
        + "".join(regular("10.0.0.6", "203.0.113.9", 443, "tcp"))
    )
    r = run("beacons", str(path), "--json", "--internal", "10.0.0.5")
    assert r.code == 0
    assert [x["src_ip"] for x in r.json()["results"]] == ["10.0.0.5"]


def test_score_ties_across_protocols_order_icmp_port_0_then_tcp_then_udp(run, csv_file):
    path = csv_file(
        HEADER
        + "".join(regular("10.0.0.5", "203.0.113.9", 443, "udp"))
        + "".join(regular("10.0.0.5", "203.0.113.9", "", "icmp"))
        + "".join(regular("10.0.0.5", "203.0.113.9", 443, "tcp"))
    )
    results = run("beacons", str(path), "--json").json()["results"]
    assert len({x["score"] for x in results}) == 1, "identical schedules tie"
    assert [tuple_of(x) for x in results] == [
        ("10.0.0.5", "203.0.113.9", 0, "icmp"),
        ("10.0.0.5", "203.0.113.9", 443, "tcp"),
        ("10.0.0.5", "203.0.113.9", 443, "udp"),
    ]


def test_icmp_tuple_with_a_random_port_in_the_export_still_groups_as_port_0(run, csv_file):
    lines = [row(START + i * 3600, "10.0.0.5", "203.0.113.9", i * 7, "icmp") for i in range(24)]
    doc = run("beacons", str(csv_file(HEADER + "".join(lines))), "--json").json()
    assert [tuple_of(x) for x in doc["results"]] == [("10.0.0.5", "203.0.113.9", 0, "icmp")]
    assert doc["results"][0]["flows"] == 24


def test_beacons_nonexistent_path_exits_2_before_any_output(run, tmp_path):
    r = run("beacons", str(tmp_path / "missing.csv"), "--json")
    assert r.code == 2 and r.out == ""
    assert len(r.err.strip().splitlines()) == 1 and "Traceback" not in r.err


def test_beacons_dash_with_json_is_still_a_usage_error_with_empty_stdout(run):
    r = run("beacons", "-", "--json", stdin_text=HEADER)
    assert r.code == 1 and r.out == ""


# ---------------------------------------------------------------- 6.3 top-ports


def test_top_ports_with_only_icmp_rows_is_an_empty_table_with_the_icmp_count(run, csv_file):
    lines = [row(START + i, "10.0.0.1", "203.0.113.9", "", "icmp") for i in range(3)]
    path = csv_file(HEADER + "".join(lines))
    r = run("top-ports", str(path))
    assert r.code == 0 and rows_of(r.out) == []
    assert "3 icmp flows ignored" in r.err
    doc = run("top-ports", str(path), "--json").json()
    assert doc["results"] == [] and doc["meta"]["flows_ignored_icmp"] == 3 and doc["meta"]["rows"] == 3


def test_top_ports_proto_filter_does_not_count_the_other_protocol_as_ignored_icmp(run, csv_file):
    text = (
        HEADER
        + GOOD
        + GOOD.replace("tcp", "udp").replace("443", "53")
        + row(START, "10.0.0.1", "203.0.113.9", "", "icmp")
    )
    doc = run("top-ports", str(csv_file(text)), "--json", "--proto", "udp").json()
    assert [x["dst_port"] for x in doc["results"]] == [53]
    assert doc["meta"]["flows_ignored_icmp"] == 1


def test_top_ports_port_zero_and_65535_are_valid_ranked_ports(run, csv_file):
    text = HEADER + GOOD.replace(",443,", ",0,") + GOOD.replace(",443,", ",65535,")
    doc = run("top-ports", str(csv_file(text)), "--json").json()
    assert [x["dst_port"] for x in doc["results"]] == [0, 65535]
    assert doc["meta"]["rows_skipped"] == 0


# ---------------------------------------------------------------- 6.2 top-talkers


def test_pair_direction_with_ipv6_only_rows(run, csv_file):
    text = HEADER + (
        "2026-09-14T18:00:00Z,fd00::2,2001:db8::1,443,tcp,300,3\n"
        "2026-09-14T18:00:01Z,fd00::1,2001:db8::1,443,tcp,100,1\n"
        "2026-09-14T18:00:02Z,fd00::1,2001:db8::2,53,udp,100,1\n"
    )
    r = run("top-talkers", str(csv_file(text)), "--direction", "pair", "--json")
    assert r.code == 0
    assert [(x["src_ip"], x["dst_ip"]) for x in r.json()["results"]] == [
        ("fd00::2", "2001:db8::1"),
        ("fd00::1", "2001:db8::1"),
        ("fd00::1", "2001:db8::2"),
    ]
    table = run("top-talkers", str(csv_file(text)), "--direction", "pair")
    assert rows_of(table.out)[0][:2] == ["fd00::2", "2001:db8::1"]


def test_ipv4_mapped_ipv6_source_merges_with_the_plain_ipv4_host_in_top_talkers(run, csv_file):
    text = HEADER + GOOD + GOOD.replace("10.0.0.1", "::ffff:10.0.0.1")
    doc = run("top-talkers", str(csv_file(text)), "--json").json()
    assert [x["host"] for x in doc["results"]] == ["10.0.0.1"] and doc["results"][0]["flows"] == 2


def test_top_talkers_dst_direction_counts_internal_to_internal_and_icmp(run, csv_file):
    text = (
        HEADER
        + row(START, "10.0.0.1", "192.168.0.9", "", "icmp")
        + row(START, "10.0.0.2", "192.168.0.9", 22, "tcp")
    )
    doc = run("top-talkers", str(csv_file(text)), "--json", "--direction", "dst").json()
    assert [x["host"] for x in doc["results"]] == ["192.168.0.9"] and doc["results"][0]["flows"] == 2


# ---------------------------------------------------------------- 6.5 output and flags shared by all commands


def test_limit_one_prints_exactly_one_row_for_every_command(run, twelve, csv_file):
    for command in ("top-talkers", "top-ports"):
        r = run(command, str(twelve), "--limit", "1")
        assert r.code == 0 and len(rows_of(r.out)) == 1, command
        assert len(run(command, str(twelve), "--limit", "1", "--json").json()["results"]) == 1
    path = csv_file(
        HEADER
        + "".join(regular("10.0.0.5", "203.0.113.9", 443, "tcp"))
        + "".join(regular("10.0.0.6", "203.0.113.9", 443, "tcp"))
    )
    r = run("beacons", str(path), "--limit", "1")
    assert r.code == 0 and len(rows_of(r.out)) == 1
    assert len(run("beacons", str(path), "--limit", "1", "--json").json()["results"]) == 1


@pytest.mark.parametrize("bad", ["abc", "1.5", "", "1e3", "0x10"])
def test_non_integer_limit_is_a_usage_error_for_every_command(run, twelve, bad):
    for command in COMMANDS:
        r = run(command, str(twelve), "--limit", bad)
        assert r.code == 1 and r.out == "", (command, bad)


def test_json_with_no_color_flag_is_still_exactly_one_json_object(run, twelve):
    for command in COMMANDS:
        r = run(command, str(twelve), "--json", "--no-color")
        assert r.code == 0
        doc = json.loads(r.out)
        assert set(doc) == {"results", "meta"} and not ANSI.search(r.out), command


def test_json_with_no_color_env_is_still_exactly_one_json_object(run, twelve, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    for command in COMMANDS:
        r = run(command, str(twelve), "--json")
        assert r.code == 0 and set(json.loads(r.out)) == {"results", "meta"}, command


def test_json_meta_shares_one_key_set_and_types_across_commands(run, twelve):
    metas = {command: run(command, str(twelve), "--json").json()["meta"] for command in COMMANDS}
    for command, meta in metas.items():
        assert SHARED_META <= set(meta), command
        assert meta["command"] == command
        assert meta["input"] == str(twelve)
        assert isinstance(meta["rows"], int) and isinstance(meta["rows_skipped"], int)
        assert isinstance(meta["elapsed_s"], int | float) and not isinstance(meta["elapsed_s"], bool)
        assert isinstance(meta["version"], str) and meta["version"]
        assert meta["rows"] == 12 and meta["rows_skipped"] == 0
    assert set(metas["top-ports"]) - SHARED_META == {"flows_ignored_icmp"}
    assert set(metas["top-talkers"]) - SHARED_META == set()
    assert set(metas["beacons"]) - SHARED_META == {
        "rows_out_of_order",
        "internal_hosts_total",
        "prevalence_applied",
    }
    assert len({m["version"] for m in metas.values()}) == 1


def test_json_meta_input_is_the_path_exactly_as_given(run, twelve, monkeypatch):
    monkeypatch.chdir(twelve.parent)
    doc = run("top-talkers", twelve.name, "--json").json()
    assert doc["meta"]["input"] == twelve.name


def test_json_numbers_are_never_formatted_strings(run, twelve, csv_file):
    for command in ("top-talkers", "top-ports"):
        for x in run(command, str(twelve), "--json").json()["results"]:
            for k, v in x.items():
                if k in {"bytes", "packets", "flows", "port"}:
                    assert isinstance(v, int) and not isinstance(v, bool), (command, k)
    path = csv_file(HEADER + "".join(regular("10.0.0.5", "203.0.113.9", 443, "tcp")))
    [x] = run("beacons", str(path), "--json").json()["results"]
    for k in ("score", "interval_score", "size_score", "histogram_score", "duration_score", "prevalence"):
        assert isinstance(x[k], int | float), k
    assert (
        isinstance(x["flows"], int) and isinstance(x["hosts_to_dst"], int) and isinstance(x["dst_port"], int)
    )


@pytest.mark.parametrize("command", COMMANDS)
def test_path_that_is_a_directory_exits_2_with_empty_stdout(run, tmp_path, command):
    r = run(command, str(tmp_path))
    assert r.code == 2 and r.out == ""
    assert "Traceback" not in r.err and len(r.err.strip().splitlines()) == 1


@pytest.mark.parametrize("command", COMMANDS)
def test_path_that_is_a_directory_with_json_prints_no_partial_json(run, tmp_path, command):
    r = run(command, str(tmp_path), "--json")
    assert r.code == 2 and r.out == ""


@pytest.mark.parametrize("command", COMMANDS)
def test_unknown_flag_is_a_usage_error_with_empty_stdout(run, twelve, command):
    r = run(command, str(twelve), "--bogus")
    assert r.code == 1 and r.out == ""


def test_missing_command_is_a_usage_error(run):
    r = run()
    assert r.code == 1 and r.out == ""


def test_stderr_summary_lines_are_plain_text_when_piped(run, dirty):
    for command in COMMANDS:
        r = run(command, str(dirty))
        assert not ANSI.search(r.err) and not ANSI.search(r.out), command


def test_undecodable_bytes_in_the_header_still_exit_2_without_traceback(run, csv_file):
    r = run("top-talkers", str(csv_file(b"ts,src_ip,\xff\xfe,dst_port,proto,bytes,packets\n", mode="wb")))
    assert r.code == 2 and r.out == "" and "Traceback" not in r.err


def test_crafted_control_characters_in_a_bad_row_never_reach_stderr_raw(run, csv_file):
    text = HEADER + GOOD + "\x1b[2J\x07bad,10.0.0.1,203.0.113.9,443,tcp,1,1\n"
    for command in COMMANDS:
        r = run(command, str(csv_file(text)))
        assert r.code == 0 and "\x1b" not in r.err and "\x07" not in r.err and "\x1b" not in r.out, command


# ---------------------------------------------------------------- second sweep: span, prevalence, units


def test_file_span_is_over_all_rows_read_not_only_outbound_ones(run, csv_file):
    # PRD 6.4 "Bins": the file span is [first ts, last ts] over all rows read. One internal-to-internal
    # row 95 h after the last outbound flow stretches the span to 95 h: bin width 95/24 h, the 24 hourly
    # flows land in bins 0-5 (4 each), so histogram = 0 (std/mean > 1) and duration = max(23/95, 6/12) = 0.5.
    text = HEADER + "".join(regular("10.0.0.5", "203.0.113.9", 443, "tcp"))
    text += row(START + 95 * 3600, "10.0.0.5", "192.168.1.1", 22, "tcp")
    [x] = run("beacons", str(csv_file(text)), "--json").json()["results"]
    assert x["histogram_score"] == 0.0 and x["duration_score"] == 0.5
    assert x["interval_score"] == 1.0 and x["size_score"] == 1.0 and x["score"] == 0.625


def test_all_zero_byte_flows_score_size_one_half_and_never_divide_by_zero(run, csv_file):
    # PRD 6.4 guards: byte median below 1 -> dispersion term defaults to 0; Q3 - Q1 < 10 -> skew term 1.
    path = csv_file(HEADER + "".join(regular("10.0.0.5", "203.0.113.9", 443, "tcp", size=0)))
    r = run("beacons", str(path), "--json")
    assert r.code == 0
    [x] = r.json()["results"]
    assert x["size_score"] == 0.5 and x["score"] == 0.875


def test_three_second_file_span_with_four_flows_is_scored_without_error(run, csv_file):
    path = csv_file(HEADER + "".join(regular("10.0.0.5", "203.0.113.9", 443, "tcp", count=4, interval=1)))
    r = run("beacons", str(path), "--json", "--min-flows", "4")
    assert r.code == 0
    [x] = r.json()["results"]
    assert x["flows"] == 4 and x["median_interval_s"] == 1.0
    assert x["histogram_score"] == 0.0 and x["duration_score"] == 0.0, "4 flows cannot fill 6 of 24 bins"


def test_prevalence_denominator_counts_single_flow_sources_but_not_inbound_only_hosts(run, csv_file):
    # PRD 6.4: denominator = Internal hosts that source at least one Outbound flow anywhere in the file.
    text = HEADER + "".join(regular("10.0.0.5", "203.0.113.9", 443, "tcp"))
    text += row(START, "203.0.113.9", "10.0.0.6", 443, "tcp")  # inbound only: not counted
    text += row(START, "10.0.0.7", "203.0.113.50", 80, "tcp")  # one Outbound flow: counted
    doc = run("beacons", str(csv_file(text)), "--json").json()
    assert doc["meta"]["internal_hosts_total"] == 2
    [x] = doc["results"]
    assert x["hosts_to_dst"] == 1 and x["prevalence"] == 0.5


def test_prevalence_numerator_ignores_port_and_protocol(run, csv_file):
    # Ten Internal hosts reach 203.0.113.9, nine of them once on unrelated ports: Prevalence is 10/10,
    # so the scored 443/tcp Tuple loses 0.15 (PRD 6.4, US-12 mirror).
    text = HEADER + "".join(regular("10.0.0.5", "203.0.113.9", 443, "tcp"))
    text += "".join(row(START, f"10.0.0.{i}", "203.0.113.9", 1000 + i, "tcp") for i in range(10, 19))
    doc = run("beacons", str(csv_file(text)), "--json").json()
    assert doc["meta"]["internal_hosts_total"] == 10 and doc["meta"]["prevalence_applied"] is True
    [x] = doc["results"]
    assert x["hosts_to_dst"] == 10 and x["prevalence"] == 1.0 and x["score"] == 0.85


def test_beacons_table_shows_prevalence_as_hosts_over_total_even_below_ten_hosts(run, csv_file):
    path = csv_file(HEADER + "".join(regular("10.0.0.5", "203.0.113.9", 443, "tcp")))
    r = run("beacons", str(path))
    [cells] = rows_of(r.out)
    assert cells[2] == "443/tcp" and "1/1" in cells and cells[-1] == "1.000"


def test_internal_cidr_with_host_bits_set_is_accepted_as_its_network(run, csv_file):
    # PRD silence: 6.4 says "CIDR"; 10.0.0.1/8 is taken as 10.0.0.0/8 rather than rejected.
    path = csv_file(HEADER + "".join(regular("10.0.0.5", "203.0.113.9", 443, "tcp")))
    r = run("beacons", str(path), "--json", "--internal", "10.0.0.1/8")
    assert r.code == 0 and [x["src_ip"] for x in r.json()["results"]] == ["10.0.0.5"]


def test_empty_internal_value_is_a_usage_error_with_empty_stdout(run, csv_file):
    path = csv_file(HEADER + GOOD)
    r = run("beacons", str(path), "--internal", "")
    assert r.code == 1 and r.out == "" and "Traceback" not in r.err


def test_byte_totals_beyond_petabytes_render_without_error(run, csv_file):
    # PRD 6.5 only asks for human units; three flows of 2^63 - 1 bytes total about 27.7 EB.
    text = HEADER + "".join(
        row(START + i, "10.0.0.1", "203.0.113.9", 443, "tcp", size=2**63 - 1) for i in range(3)
    )
    r = run("top-talkers", str(csv_file(text)))
    assert r.code == 0
    [cells] = rows_of(r.out)
    assert cells[0] == "10.0.0.1" and cells[2] == "PB" and cells[-1] == "3"
    assert run("top-talkers", str(csv_file(text)), "--json").json()["results"][0]["bytes"] == 3 * (2**63 - 1)


def test_date_only_iso_timestamp_is_midnight_utc(run, csv_file):
    # PRD 6.1: accepted ISO forms are exactly those datetime.fromisoformat accepts; a bare date is one.
    text = (
        HEADER
        + "2026-09-14,10.0.0.1,203.0.113.9,443,tcp,1,1\n"
        + "1789344000,10.0.0.2,203.0.113.9,443,tcp,1,1\n"
    )
    doc = run("beacons", str(csv_file(text)), "--json").json()
    assert doc["meta"]["rows_skipped"] == 0 and doc["meta"]["rows"] == 2


@pytest.mark.parametrize(
    ("command", "flag", "value"),
    [
        ("top-ports", "--proto", "TCP"),
        ("top-talkers", "--direction", "PAIR"),
        ("top-talkers", "--by", "Bytes"),
    ],
)
def test_choice_flags_are_case_sensitive_usage_errors(run, twelve, command, flag, value):
    r = run(command, str(twelve), flag, value)
    assert r.code == 1 and r.out == ""
