"""Slice 5 acceptance (#13, PRD 6.2 / US-07): top-talkers --direction pair ranks (source, destination) Pairs."""

from __future__ import annotations

from conftest import HEADER
from test_top_talkers import rows_of

# Pairs in the 12-row fixture (bytes / packets / flows):
#   10.0.0.1 -> 203.0.113.9   4000 / 20 / 2
#   10.0.0.1 -> 203.0.113.10  2000 / 10 / 1
#   10.0.0.2 -> 203.0.113.9   1500 / 10 / 2
#   10.0.0.2 -> 203.0.113.11  1500 / 10 / 2
#   10.0.0.3 -> 203.0.113.12   540 /  6 / 3   (port 80 only; the port is not part of a Pair)
#   10.0.0.3 -> 203.0.113.13   360 /  4 / 2   (one tcp/80 flow and one icmp flow: same Pair)


def pairs_of(result) -> list[tuple[str, str]]:
    return [(x["src_ip"], x["dst_ip"]) for x in result.json()["results"]]


def test_pair_limit_three_prints_three_pair_rows_ranked_by_bytes(run, twelve):
    r = run("top-talkers", str(twelve), "--direction", "pair", "--limit", "3")
    assert r.code == 0
    body = rows_of(r.out)
    assert len(body) == 3
    # Both addresses appear on every row, source first.
    assert [(row[0], row[1]) for row in body] == [
        ("10.0.0.1", "203.0.113.9"),
        ("10.0.0.1", "203.0.113.10"),
        ("10.0.0.2", "203.0.113.9"),  # 1500-byte tie with 203.0.113.11: lower destination first
    ]


def test_pair_ignores_port_and_protocol(run, twelve):
    r = run("top-talkers", str(twelve), "--direction", "pair", "--json")
    results = r.json()["results"]
    assert len(results) == 6
    last = results[-1]
    assert last["src_ip"] == "10.0.0.3" and last["dst_ip"] == "203.0.113.13"
    assert last["flows"] == 2 and last["bytes"] == 360 and last["packets"] == 4


def test_pair_by_packets(run, twelve):
    r = run("top-talkers", str(twelve), "--direction", "pair", "--by", "packets", "--json")
    assert pairs_of(r) == [
        ("10.0.0.1", "203.0.113.9"),
        ("10.0.0.1", "203.0.113.10"),
        ("10.0.0.2", "203.0.113.9"),
        ("10.0.0.2", "203.0.113.11"),
        ("10.0.0.3", "203.0.113.12"),
        ("10.0.0.3", "203.0.113.13"),
    ]


def test_pair_by_flows(run, twelve):
    r = run("top-talkers", str(twelve), "--direction", "pair", "--by", "flows", "--json")
    assert pairs_of(r) == [
        ("10.0.0.3", "203.0.113.12"),  # 3 flows
        ("10.0.0.1", "203.0.113.9"),  # 2 flows: ties by source, then destination
        ("10.0.0.2", "203.0.113.9"),
        ("10.0.0.2", "203.0.113.11"),
        ("10.0.0.3", "203.0.113.13"),
        ("10.0.0.1", "203.0.113.10"),  # 1 flow
    ]
    top = r.json()["results"][0]
    assert top["flows"] == 3 and top["bytes"] == 540 and top["packets"] == 6


def test_pair_ties_order_by_source_then_destination_in_ip_order(run, csv_file):
    text = HEADER + (
        "2026-09-14T18:00:00Z,10.0.0.9,203.0.113.2,443,tcp,100,1\n"
        "2026-09-14T18:00:01Z,10.0.0.2,203.0.113.10,443,tcp,100,1\n"
        "2026-09-14T18:00:02Z,10.0.0.2,203.0.113.9,443,tcp,100,1\n"
    )
    r = run("top-talkers", str(csv_file(text)), "--direction", "pair", "--json")
    assert pairs_of(r) == [
        ("10.0.0.2", "203.0.113.9"),  # numeric IP order, not string order (9 before 10)
        ("10.0.0.2", "203.0.113.10"),
        ("10.0.0.9", "203.0.113.2"),  # higher source loses even with the lowest destination
    ]


def test_pair_json_results_carry_src_ip_and_dst_ip_and_parse(run, twelve):
    import json

    r = run("top-talkers", str(twelve), "--direction", "pair", "--json")
    assert r.code == 0
    # Whole stdout is exactly one JSON object: the same parse an analyst's `jq .` does.
    doc = json.loads(r.out)
    assert doc["results"], "expected some results"
    for row in doc["results"]:
        assert set(row) == {"src_ip", "dst_ip", "bytes", "packets", "flows"}
    assert doc["meta"]["command"] == "top-talkers"


def test_pair_table_shows_both_addresses_and_measures(run, twelve):
    r = run("top-talkers", str(twelve), "--direction", "pair", "--limit", "1")
    lines = r.out.splitlines()
    assert lines[0].split() == ["src_ip", "dst_ip", "bytes", "packets", "flows"]
    assert lines[1].split() == ["10.0.0.1", "203.0.113.9", "4.0", "KB", "20", "2"]
    assert r.out.isascii()


def test_pair_header_only_file_gives_empty_results(run, csv_file):
    r = run("top-talkers", str(csv_file(HEADER)), "--direction", "pair", "--json")
    assert r.code == 0 and r.json()["results"] == []


def test_pair_help_states_that_memory_grows_with_distinct_pairs(run):
    r = run("top-talkers", "--help")
    assert r.code == 0
    text = " ".join(r.out.split()).lower()
    assert "pair" in text
    assert "memory" in text and "distinct pairs" in text


def test_src_and_dst_directions_are_unchanged(run, twelve):
    r = run("top-talkers", str(twelve), "--direction", "src", "--json")
    assert set(r.json()["results"][0]) == {"host", "bytes", "packets", "flows"}
    r = run("top-talkers", str(twelve), "--direction", "dst")
    assert r.out.splitlines()[0].split() == ["host", "bytes", "packets", "flows"]
