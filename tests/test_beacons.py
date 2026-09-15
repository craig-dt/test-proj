"""Slice 6 acceptance: the `beacons` command end to end (issue #14, PRD 6.4, US-03/08/09/10/12).

Everything runs through the public CLI. Fixtures are built in-test: rows are epoch seconds, grouped by
Tuple (each Tuple's rows in timestamp order) and interleaved between Tuples, which is how a flow
collector emits them and exactly what the order rule must tolerate.
"""

from __future__ import annotations

import random
import statistics
import tracemalloc
from pathlib import Path

from conftest import HEADER, rows_of

START = 1_789_344_000  # 2026-09-14T00:00:00Z
DAY = 24 * 3600
BEACON = ("10.0.0.5", "203.0.113.9", 443, "tcp")
SUB_SCORES = ("interval_score", "size_score", "histogram_score", "duration_score")


def row(ts: int, src: str, dst: str, port: int | str, proto: str, size: int = 1000, packets: int = 2) -> str:
    return f"{ts},{src},{dst},{port},{proto},{size},{packets}\n"


def regular(src, dst, port, proto, *, start=START, count=24, interval=3600, size=1000) -> list[str]:
    return [row(start + i * interval, src, dst, port, proto, size) for i in range(count)]


def jittered(src, dst, port, proto, *, seed=1, start=START, end=START + DAY, interval=60, jitter=2):
    """A beacon every `interval` s +/- `jitter` s from `start` to `end`, small byte-size jitter."""
    rng = random.Random(seed)
    lines, ts = [], start
    while ts <= end:
        lines.append(row(ts, src, dst, port, proto, 1000 + rng.randint(-30, 30)))
        ts += interval + rng.randint(-jitter, jitter)
    return lines


def browser(src: str, *, seed=3, tuples=8, flows=15, singles=300, start=START, end=START + DAY) -> list[str]:
    """Hundreds of irregular flows to many destinations; `tuples` of them pass the default gate."""
    rng = random.Random(seed)
    lines = []
    for i in range(tuples):
        ts = rng.randint(start, start + DAY // 2)
        for _ in range(flows):
            lines.append(row(ts, src, f"198.51.100.{i + 1}", 443, "tcp", rng.randint(200, 60_000)))
            ts = min(ts + rng.randint(1, 400), end)
    for _ in range(singles):
        dst = f"{rng.choice((23, 34, 52, 104))}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        lines.append(
            row(rng.randint(start, end), src, dst, rng.choice((80, 443)), "tcp", rng.randint(200, 9000))
        )
    return lines


def write(csv_file, *groups: list[str], name: str = "flows.csv") -> Path:
    return csv_file(HEADER + "".join(line for group in groups for line in group), name=name)


def tuple_of(result: dict) -> tuple:
    return (result["src_ip"], result["dst_ip"], result["dst_port"], result["proto"])


def unadjusted(result: dict) -> float:
    return round(statistics.fmean(result[k] for k in SUB_SCORES), 3)


# ---------------------------------------------------------------- acceptance criteria from the brief


def test_planted_24h_beacon_ranks_first_with_median_60_and_score_at_least_0_85(run, csv_file):
    path = write(csv_file, jittered(*BEACON), browser("10.0.0.7"))
    r = run("beacons", str(path), "--json")
    assert r.code == 0
    results = r.json()["results"]
    top = results[0]
    assert tuple_of(top) == BEACON
    assert 1400 <= top["flows"] <= 1500
    assert top["median_interval_s"] == 60
    assert top["score"] >= 0.85


def test_browser_like_host_has_gate_passing_tuples_but_none_in_the_top_5(run, csv_file):
    # The beacon plus four NTP-like Tuples are the real signals; the browser must rank below all of them.
    ntp = [
        regular(f"10.0.0.{11 + i}", "198.51.100.123", 123, "udp", count=97, interval=900) for i in range(4)
    ]
    path = write(csv_file, jittered(*BEACON), browser("10.0.0.7"), *ntp)
    everything = run("beacons", str(path), "--json", "--limit", "1000").json()["results"]
    assert sum(1 for x in everything if x["src_ip"] == "10.0.0.7") >= 5, "fixture: browser passes the gate"
    top5 = run("beacons", str(path), "--json", "--limit", "5").json()["results"]
    assert len(top5) == 5
    assert all(x["src_ip"] != "10.0.0.7" for x in top5)


def test_table_output_ranks_the_beacon_first_and_never_uses_the_word_beacon(run, csv_file):
    path = write(csv_file, jittered(*BEACON), browser("10.0.0.7"))
    r = run("beacons", str(path))
    assert r.code == 0
    rows = rows_of(r.out)
    assert rows[0][:3] == ["10.0.0.5", "203.0.113.9", "443/tcp"]
    assert rows[0][4] == "60"  # median Interval in seconds
    assert float(rows[0][-1]) >= 0.85 and len(rows[0][-1].split(".")[1]) == 3  # score to 3 dp
    assert "/" in rows[0][-2]  # prevalence as hosts/total
    assert "beacon" not in r.out.lower()


def test_nine_flows_absent_with_default_gate_and_present_with_min_flows_9(run, csv_file):
    path = write(
        csv_file, regular(*BEACON, count=9), regular("10.0.0.6", "203.0.113.10", 443, "tcp", count=12)
    )
    default = run("beacons", str(path), "--json").json()["results"]
    assert [tuple_of(x) for x in default] == [("10.0.0.6", "203.0.113.10", 443, "tcp")]
    lowered = run("beacons", str(path), "--json", "--min-flows", "9").json()["results"]
    assert {tuple_of(x) for x in lowered} == {BEACON, ("10.0.0.6", "203.0.113.10", 443, "tcp")}


def test_twelve_flows_in_one_second_are_absent(run, csv_file):
    same_second = [row(START + 3600, *BEACON) for _ in range(12)]
    other = regular("10.0.0.6", "203.0.113.10", 443, "tcp", count=12)
    r = run("beacons", str(write(csv_file, same_second, other)), "--json")
    assert r.code == 0
    assert [tuple_of(x) for x in r.json()["results"]] == [("10.0.0.6", "203.0.113.10", 443, "tcp")]


def test_same_host_regular_on_53_tcp_and_53_udp_is_two_tuples(run, csv_file):
    path = write(
        csv_file,
        regular("10.0.0.5", "203.0.113.9", 53, "tcp", count=24),
        regular("10.0.0.5", "203.0.113.9", 53, "udp", count=24, start=START + 30),
    )
    results = run("beacons", str(path), "--json").json()["results"]
    assert sorted(tuple_of(x) for x in results) == [
        ("10.0.0.5", "203.0.113.9", 53, "tcp"),
        ("10.0.0.5", "203.0.113.9", 53, "udp"),
    ]


def test_internal_override_replaces_the_default_list(run, csv_file):
    path = write(
        csv_file,
        regular("203.0.113.5", "198.51.100.9", 443, "tcp", count=24),  # scored under the override
        regular("10.0.0.5", "198.51.100.9", 443, "tcp", count=24),  # RFC 1918 becomes external
    )
    default = run("beacons", str(path), "--json").json()["results"]
    assert [x["src_ip"] for x in default] == ["10.0.0.5"]
    override = run("beacons", str(path), "--json", "--internal", "203.0.113.0/24")
    assert override.code == 0
    assert [x["src_ip"] for x in override.json()["results"]] == ["203.0.113.5"]


def test_internal_is_repeatable_across_address_families(run, csv_file):
    path = write(
        csv_file,
        regular("203.0.113.5", "198.51.100.9", 443, "tcp", count=24),
        regular("2001:db8:1::5", "2001:db8:2::9", 443, "tcp", count=24),
        regular("10.0.0.5", "198.51.100.9", 443, "tcp", count=24),
    )
    r = run("beacons", str(path), "--json", "--internal", "203.0.113.0/24", "--internal", "2001:db8:1::/48")
    assert r.code == 0
    assert {x["src_ip"] for x in r.json()["results"]} == {"203.0.113.5", "2001:db8:1::5"}


def test_ipv6_unique_local_source_to_global_destination_is_a_candidate_by_default(run, csv_file):
    path = write(csv_file, regular("fd00::5", "2001:db8::9", 443, "tcp", count=24))
    r = run("beacons", str(path), "--json")
    assert r.code == 0
    assert [tuple_of(x) for x in r.json()["results"]] == [("fd00::5", "2001:db8::9", 443, "tcp")]


def test_flows_between_two_internal_hosts_or_from_external_are_not_candidates(run, csv_file):
    path = write(
        csv_file,
        regular("10.0.0.5", "192.168.1.9", 443, "tcp", count=24),  # internal to internal
        regular("198.51.100.5", "203.0.113.9", 443, "tcp", count=24),  # external source
        regular("10.0.0.6", "203.0.113.9", 443, "tcp", count=24),  # the one Outbound Tuple
    )
    results = run("beacons", str(path), "--json").json()["results"]
    assert [x["src_ip"] for x in results] == ["10.0.0.6"]


def test_bad_internal_cidr_is_a_usage_error(run, csv_file):
    path = write(csv_file, regular(*BEACON))
    r = run("beacons", str(path), "--internal", "not-a-network")
    assert r.code == 1 and r.out == ""


def test_row_41_earlier_than_row_40_is_dropped_and_reported_once(run, csv_file):
    lines = regular(*BEACON, count=40, interval=60)
    lines.append(row(START + 30 * 60 + 1, *BEACON))  # row 41: earlier than row 40, same Tuple
    r = run("beacons", str(write(csv_file, lines)), "--json")
    assert r.code == 0
    doc = r.json()
    assert doc["meta"]["rows_out_of_order"] == 1
    assert doc["meta"]["rows_skipped"] == 0
    assert doc["results"][0]["flows"] == 40  # the accepted count
    assert r.err.count("1 rows out of order (dropped from beacon scoring)") == 1
    table = run("beacons", str(write(csv_file, lines)))
    assert table.code == 0 and rows_of(table.out)[0][3] == "40"


def test_interleaved_tuples_are_not_out_of_order(run, csv_file):
    a = regular("10.0.0.5", "203.0.113.9", 443, "tcp", count=24)
    b = regular("10.0.0.6", "203.0.113.10", 443, "tcp", count=24, start=START + 1800)
    interleaved = [line for pair in zip(a, b, strict=True) for line in pair]
    # Row n+1 of Tuple b is later than row n of Tuple a, but row n+2 of Tuple a is earlier than that.
    r = run("beacons", str(write(csv_file, interleaved)), "--json")
    assert r.code == 0
    assert r.json()["meta"]["rows_out_of_order"] == 0
    assert "out of order" not in r.err
    assert [x["flows"] for x in r.json()["results"]] == [24, 24]


HUNDRED = [f"10.0.1.{i}" for i in range(1, 101)]
PLANTED = (HUNDRED[0], "203.0.113.9", 443, "tcp")  # the planted Tuple's source is one of the hundred


def hundred_hosts(rng: random.Random, *, dst: str, also_to: str, hitters: int) -> list[str]:
    """The 100 Internal hosts each source one Outbound flow inside the span; the `hitters` hosts after the
    planted source also contact `also_to` once, on a port other than the planted Tuple's."""
    lines = []
    for i, host in enumerate(HUNDRED):
        lines.append(row(START + rng.randint(1, DAY - 1), host, dst, 80, "tcp", 500))
        if 1 <= i <= hitters:
            lines.append(row(START + rng.randint(1, DAY - 1), host, also_to, 80, "tcp", 500))
    return lines


def test_destination_reached_by_60_of_100_internal_hosts_scores_0_15_lower(run, csv_file):
    rng = random.Random(12)
    perfect = regular(*PLANTED, count=24, interval=3600, size=512)  # pre-prevalence 1.000 (TC11)
    path = write(csv_file, perfect, hundred_hosts(rng, dst="198.51.100.1", also_to=PLANTED[1], hitters=59))
    r = run("beacons", str(path), "--json")
    assert r.code == 0
    doc = r.json()
    top = next(x for x in doc["results"] if tuple_of(x) == PLANTED)
    assert unadjusted(top) == 1.0
    assert top["score"] == 0.85
    assert top["hosts_to_dst"] == 60 and top["prevalence"] == 0.6  # 59 hitters plus the source itself
    assert doc["meta"]["internal_hosts_total"] == 100
    assert doc["meta"]["prevalence_applied"] is True
    assert "prevalence" not in r.err
    assert rows_of(run("beacons", str(path)).out)[0][-2] == "60/100"


def test_destination_reached_by_1_of_100_internal_hosts_scores_0_15_higher_and_shows_1_of_100(run, csv_file):
    rng = random.Random(13)
    # A 30-flow burst: interval and size perfect, histogram and duration weak, so +0.15 is visible.
    burst = regular(*PLANTED, count=30, interval=60, start=START + 7200, size=512)
    edges = [
        row(START, HUNDRED[1], "198.51.100.1", 80, "tcp"),
        row(START + DAY, HUNDRED[2], "198.51.100.1", 80, "tcp"),
    ]
    path = write(
        csv_file, burst, edges, hundred_hosts(rng, dst="198.51.100.1", also_to="198.51.100.2", hitters=0)
    )
    r = run("beacons", str(path), "--json")
    assert r.code == 0
    top = r.json()["results"][0]
    assert tuple_of(top) == PLANTED
    assert unadjusted(top) < 0.85, "fixture: the cap at 1 must not hide the adjustment"
    assert top["score"] == round(unadjusted(top) + 0.15, 3)
    assert top["hosts_to_dst"] == 1 and top["prevalence"] == 0.01
    table = run("beacons", str(path))
    assert rows_of(table.out)[0][-2] == "1/100"


def test_only_two_internal_hosts_means_no_adjustment_and_a_stderr_note(run, csv_file):
    path = write(
        csv_file, regular(*BEACON, count=24, size=512), regular("10.0.0.6", BEACON[1], 80, "tcp", count=24)
    )
    r = run("beacons", str(path), "--json")
    assert r.code == 0
    doc = r.json()
    assert doc["meta"]["prevalence_applied"] is False
    assert doc["meta"]["internal_hosts_total"] == 2
    for x in doc["results"]:
        assert x["score"] == unadjusted(x)
        assert x["hosts_to_dst"] == 2 and x["prevalence"] == 1.0
    assert r.err.count("prevalence adjustment skipped") == 1
    assert "2 internal hosts" in r.err
    table = run("beacons", str(path))
    assert rows_of(table.out)[0][-2] == "2/2"


def test_stdin_is_a_usage_error_with_one_line_on_stderr(run, csv_file):
    r = run("beacons", "-", stdin_text=HEADER + "".join(regular(*BEACON)))
    assert r.code == 1
    assert r.out == ""
    assert r.err.count("\n") == 1
    assert "path" in r.err and "twice" in r.err


def test_json_parses_with_three_malformed_rows_and_nothing_else_on_stdout(run, csv_file):
    dirty = [
        "not-a-timestamp,10.0.0.5,203.0.113.9,443,tcp,100,1\n",
        f"{START + 5},300.0.0.1,203.0.113.9,443,tcp,100,1\n",
        f"{START + 6},10.0.0.5,203.0.113.9,443,tcp,-5,1\n",
    ]
    r = run("beacons", str(write(csv_file, regular(*BEACON), dirty)), "--json")
    assert r.code == 0
    assert r.out.startswith("{") and r.out.rstrip("\n").endswith("}") and r.out.count("\n") == 1
    doc = r.json()
    assert doc["meta"]["command"] == "beacons"
    assert doc["meta"]["rows_skipped"] == 3 and doc["meta"]["rows"] == 27
    assert "3 rows skipped" in r.err
    result = doc["results"][0]
    assert set(result) >= {"src_ip", "dst_ip", "dst_port", "proto", "flows", "median_interval_s", "score",
                           "prevalence", "hosts_to_dst", *SUB_SCORES}  # fmt: skip
    assert isinstance(result["dst_port"], int) and "port_proto" not in result
    assert set(doc["meta"]) >= {"rows_out_of_order", "internal_hosts_total", "prevalence_applied"}


def test_byte_or_packet_count_at_2_pow_63_is_a_skipped_row_never_a_crash(run, csv_file):
    lines = regular(*BEACON, count=24)
    lines.append(row(START + DAY + 60, *BEACON, size=2**63))
    lines.append(row(START + DAY + 120, *BEACON, size=1, packets=2**63))
    lines.append(row(START + DAY + 180, *BEACON, size=2**63 - 1))  # the largest admitted count
    r = run("beacons", str(write(csv_file, lines)), "--json")
    assert r.code == 0
    doc = r.json()
    assert doc["meta"]["rows_skipped"] == 2 and doc["meta"]["rows_out_of_order"] == 0
    assert doc["results"][0]["flows"] == 25


def test_pass_one_holds_only_counts_and_the_internal_host_set(csv_file):
    """Memory in pass 1 must not depend on distinct destinations per source: 50 k single-flow Tuples
    from one host leave a count per Tuple, one Internal host, the span and the read stats. Nothing
    else (no per-destination host sets; those are built in pass 2 for gate-passing destinations)."""
    from flowtest.commands.beacons import DEFAULT_INTERNAL, HostClassifier, count_tuples

    lines = [row(START + i, "10.0.0.1", f"{23 + i // 65025}.{(i // 255) % 255}.{i % 255}.{1 + i % 253}", 443, "tcp")
             for i in range(50_000)]  # fmt: skip
    path = write(csv_file, lines)
    tracemalloc.start()
    pass_one = count_tuples(str(path), HostClassifier(DEFAULT_INTERNAL))
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert set(pass_one._fields) == {"counts", "internal_hosts", "file_first", "file_last", "stats"}
    assert len(pass_one.counts) == 50_000 and set(pass_one.counts.values()) == {1}
    assert pass_one.internal_hosts == {"10.0.0.1"}
    assert (pass_one.file_first, pass_one.file_last) == (START, START + 49_999)
    assert pass_one.stats.rows == 50_000
    # Retained bytes per Tuple in the pass-1 table (dict slot + packed key + small int). The peak above
    # also counts the reader's bounded caches, so the retained size is the discriminating number: a
    # tuple-of-strings key measured about 210 B and a per-destination set would add far more.
    import sys

    counts = pass_one.counts
    retained = sys.getsizeof(counts) + sum(sys.getsizeof(k) + sys.getsizeof(v) for k, v in counts.items())
    per_tuple = retained / len(counts)
    assert per_tuple < 160, f"pass 1 retains {per_tuple:.0f} B per Tuple"
    assert peak < 60 * 2**20, (
        f"pass 1 peaked at {peak / 2**20:.1f} MB for 50 k Tuples (reader caches included)"
    )


def test_fifty_thousand_single_flow_tuples_give_an_empty_ranking(run, csv_file):
    lines = [row(START + i, "10.0.0.1", f"203.0.{i // 250}.{1 + i % 250}", 443, "tcp") for i in range(50_000)]
    r = run("beacons", str(write(csv_file, lines)), "--json")
    assert r.code == 0
    doc = r.json()
    assert doc["results"] == [] and doc["meta"]["internal_hosts_total"] == 1


# ---------------------------------------------------------------- gaps between the criteria


def test_ranking_is_score_descending_then_tuple_key_ascending_and_limit_cuts(run, csv_file):
    # Four identical perfect Tuples tie at the same score; ties break by source, destination, port, proto.
    path = write(
        csv_file,
        regular("10.0.0.9", "203.0.113.1", 443, "tcp", size=512),
        regular("10.0.0.5", "203.0.113.2", 443, "tcp", size=512),
        regular("10.0.0.5", "203.0.113.1", 443, "udp", size=512),
        regular("10.0.0.5", "203.0.113.1", 443, "tcp", size=512),
        regular("10.0.0.10", "203.0.113.1", 443, "tcp", size=512),  # sorts after 10.0.0.9 in IP order
        jittered("10.0.0.6", "203.0.113.3", 443, "tcp"),  # lower score than a perfect Tuple
    )
    results = run("beacons", str(path), "--json", "--limit", "100").json()["results"]
    assert [tuple_of(x) for x in results] == [
        ("10.0.0.5", "203.0.113.1", 443, "tcp"),
        ("10.0.0.5", "203.0.113.1", 443, "udp"),
        ("10.0.0.5", "203.0.113.2", 443, "tcp"),
        ("10.0.0.9", "203.0.113.1", 443, "tcp"),
        ("10.0.0.10", "203.0.113.1", 443, "tcp"),
        ("10.0.0.6", "203.0.113.3", 443, "tcp"),
    ]
    assert len(run("beacons", str(path), "--json", "--limit", "2").json()["results"]) == 2
    assert run("beacons", str(path), "--limit", "0").code == 1


def test_icmp_outbound_flows_form_a_port_0_tuple(run, csv_file):
    path = write(csv_file, regular("10.0.0.5", "203.0.113.9", "", "icmp", count=24))
    results = run("beacons", str(path), "--json").json()["results"]
    assert [tuple_of(x) for x in results] == [("10.0.0.5", "203.0.113.9", 0, "icmp")]
    table = run("beacons", str(path))
    assert rows_of(table.out)[0][2] == "0/icmp"


def test_header_only_file_is_a_success_with_empty_results(run, csv_file):
    r = run("beacons", str(csv_file(HEADER)), "--json")
    assert r.code == 0
    doc = r.json()
    assert doc["results"] == []
    assert doc["meta"]["rows"] == 0 and doc["meta"]["internal_hosts_total"] == 0
    assert doc["meta"]["prevalence_applied"] is False


def test_min_flows_must_be_positive(run, csv_file):
    path = write(csv_file, regular(*BEACON))
    for bad in ("0", "-3", "x"):
        r = run("beacons", str(path), "--min-flows", bad)
        assert r.code == 1 and r.out == ""


def test_median_interval_is_the_sample_median_and_ignores_zero_intervals(run, csv_file):
    # 60 s gaps with a doubled flow in each second: zero Intervals are not Intervals.
    lines = []
    for i in range(24):
        lines.append(row(START + i * 60, *BEACON))
        lines.append(row(START + i * 60, *BEACON))
    r = run("beacons", str(write(csv_file, lines)), "--json")
    top = r.json()["results"][0]
    assert top["median_interval_s"] == 60 and top["flows"] == 48


def test_help_explains_the_two_pass_read_and_short_bursts(run):
    r = run("beacons", "--help")
    assert r.code == 0
    text = r.out.lower()
    assert "--min-flows" in text and "--internal" in text
    assert "twice" in text
    assert "burst" in text  # US-03: short bursts score lower because histogram and duration need coverage


# --- verify-review additions (PR #35) -------------------------------------------------------------


def test_min_flows_below_four_creates_no_accumulator_for_unscorable_tuples(csv_file):
    """--min-flows 1 must not allocate pass-2 state for Tuples that can never have 3 non-zero Intervals
    (review F2); the ranking is identical, only the memory differs."""
    from flowtest.commands.beacons import DEFAULT_INTERNAL, HostClassifier, accumulate, count_tuples

    lines = [row(START + i, "10.0.0.1", f"203.0.113.{1 + i % 200}", 443, "tcp") for i in range(600)]
    path = write(csv_file, lines)  # 200 Tuples with 3 flows each
    hosts = HostClassifier(DEFAULT_INTERNAL)
    pass_two = accumulate(str(path), hosts, count_tuples(str(path), hosts), min_flows=1)
    assert pass_two.accumulators == {} and pass_two.hosts_to_dst == {}


def test_pass_one_counts_are_freed_before_pass_two_allocates(csv_file, monkeypatch):
    from flowtest.commands import beacons

    lines = [row(START + i * 60, "10.0.0.1", "203.0.113.9", 443, "tcp") for i in range(20)]
    path = write(csv_file, lines)
    hosts = beacons.HostClassifier(beacons.DEFAULT_INTERNAL)
    pass_one = beacons.count_tuples(str(path), hosts)
    assert len(pass_one.counts) == 1
    seen_counts_len = []
    real = beacons.TupleAccumulator

    class Spy(real):
        __slots__ = ()

        def __init__(self, *a, **k):
            seen_counts_len.append(len(pass_one.counts))
            super().__init__(*a, **k)

    monkeypatch.setattr(beacons, "TupleAccumulator", Spy)
    beacons.accumulate(str(path), hosts, pass_one, min_flows=10)
    assert seen_counts_len == [0], "the pass-1 table must be empty before any accumulator exists"


def test_file_that_grows_between_the_passes_exits_2(run, csv_file, monkeypatch):
    from flowtest.commands import beacons

    lines = [row(START + i * 60, "10.0.0.1", "203.0.113.9", 443, "tcp") for i in range(20)]
    path = write(csv_file, lines)
    real_read = beacons.read_flows
    calls = {"n": 0}

    def grow_then_read(source):
        calls["n"] += 1
        if calls["n"] == 2:  # between pass 1 and pass 2: a row lands outside the recorded span
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(row(START + 10 * 86400, "10.0.0.1", "203.0.113.9", 443, "tcp") + "\n")
        return real_read(source)

    monkeypatch.setattr(beacons, "read_flows", grow_then_read)
    r = run("beacons", str(path))
    assert r.code == 2 and "changed while being read" in r.err and "Traceback" not in r.err


def test_median_interval_is_always_a_float_in_json(run, csv_file):
    lines = [row(START + i * 900, "10.0.0.1", "203.0.113.9", 443, "tcp") for i in range(97)]  # odd count
    r = run("beacons", str(write(csv_file, lines)), "--json")
    value = r.json()["results"][0]["median_interval_s"]
    assert isinstance(value, float) and value == 900.0


def test_packed_tuple_key_round_trips_both_address_families():
    from flowtest.commands.beacons import pack_key, unpack_key

    cases = [
        ("10.0.0.5", "203.0.113.9", 443, "tcp"),
        ("fd00::1", "2001:db8::9", 53, "udp"),
        ("10.0.0.5", "2001:db8::9", 0, "icmp"),
        ("fd00::1", "203.0.113.9", 65535, "tcp"),
    ]
    keys = [pack_key(*c) for c in cases]
    assert [unpack_key(k) for k in keys] == cases
    assert len(set(keys)) == len(keys)
    assert {len(k) for k in keys} == {3 + 8, 3 + 32, 3 + 20}


def test_help_says_order_is_against_the_previous_accepted_row(run):
    r = run("beacons", "--help")
    assert "previous accepted row" in " ".join(r.out.split())
