"""Slice 3 acceptance: top-ports ranks destination ports by Flow count with built-in service names (PRD 6.3)."""

from __future__ import annotations

from conftest import ANSI, HEADER


def table_rows(table: str) -> list[dict[str, str]]:
    """Parse a Table output into dicts keyed by header, using the header's column start offsets so a
    blank cell (unknown service) still lands in the right column."""
    lines = [ln for ln in table.splitlines() if ln.strip()]
    header = lines[0]
    names = header.split()
    starts = [header.index(name) for name in names]
    bounds = list(zip(starts, starts[1:] + [None], strict=False))
    return [{name: ln[a:b].strip() for name, (a, b) in zip(names, bounds, strict=True)} for ln in lines[1:]]


# ---------------------------------------------------------------- acceptance criteria from the brief


def test_fixture_shows_service_names_and_ignores_icmp(run, twelve):
    r = run("top-ports", str(twelve))
    assert r.code == 0
    rows = table_rows(r.out)
    by_port = {row["port"]: row for row in rows}
    assert by_port["443/tcp"]["service"] == "https"
    assert by_port["53/udp"]["service"] == "dns"
    assert all(row["port"].endswith(("/tcp", "/udp")) for row in rows)
    assert "1 icmp flows ignored" in r.err
    # 12 fixture flows minus the one icmp flow are ranked; pinned through JSON (raw integers).
    assert sum(x["flows"] for x in run("top-ports", str(twelve), "--json").json()["results"]) == 11


def test_ranking_is_by_flow_count_not_bytes(run, twelve):
    # 443/tcp: 5 flows / 7500 B, 80/tcp: 4 flows / 720 B, 53/udp: 2 flows / 1500 B.
    r = run("top-ports", str(twelve), "--json")
    results = r.json()["results"]
    assert [(x["dst_port"], x["proto"]) for x in results] == [(443, "tcp"), (80, "tcp"), (53, "udp")]
    assert [x["flows"] for x in results] == [5, 4, 2]
    assert [x["bytes"] for x in results] == [7500, 720, 1500]


def test_proto_udp_shows_only_udp_rows(run, twelve):
    r = run("top-ports", str(twelve), "--proto", "udp")
    assert r.code == 0
    rows = table_rows(r.out)
    assert rows and all(row["port"].endswith("/udp") for row in rows)
    assert [row["port"] for row in rows] == ["53/udp"]


def test_proto_tcp_still_reports_ignored_icmp(run, twelve):
    r = run("top-ports", str(twelve), "--proto", "tcp", "--json")
    assert all(x["proto"] == "tcp" for x in r.json()["results"])
    assert "1 icmp flows ignored" in r.err


def test_equal_flow_counts_order_by_port_ascending(run, csv_file):
    text = HEADER + (
        "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,8080,tcp,100,1\n"
        "2026-09-14T18:00:01Z,10.0.0.1,203.0.113.9,22,tcp,100,1\n"
        "2026-09-14T18:00:02Z,10.0.0.1,203.0.113.9,443,tcp,100,1\n"
        "2026-09-14T18:00:03Z,10.0.0.1,203.0.113.9,80,tcp,100,1\n"
    )
    r = run("top-ports", str(csv_file(text)), "--json")
    assert [x["dst_port"] for x in r.json()["results"]] == [22, 80, 443, 8080]


def test_limit_is_respected(run, csv_file):
    text = HEADER + "".join(
        f"2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,{1000 + i},tcp,100,1\n" for i in range(5)
    )
    r = run("top-ports", str(csv_file(text)), "--limit", "2", "--json")
    assert [x["dst_port"] for x in r.json()["results"]] == [1000, 1001]


def test_limit_zero_and_negative_exit_1(run, twelve):
    for bad in ("0", "-1"):
        r = run("top-ports", str(twelve), "--limit", bad)
        assert r.code == 1
        assert r.out == ""


def test_json_service_is_string_or_null_and_nothing_else_on_stdout(run, csv_file):
    text = HEADER + (
        "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,tcp,100,1\n"
        "2026-09-14T18:00:01Z,10.0.0.1,203.0.113.9,44444,tcp,100,1\n"
    )
    r = run("top-ports", str(csv_file(text)), "--json")
    assert r.code == 0
    assert r.out.strip().startswith("{") and r.out.strip().endswith("}")
    doc = r.json()  # parses; nothing else on stdout
    services = {x["dst_port"]: x["service"] for x in doc["results"]}
    assert services == {443: "https", 44444: None}
    assert doc["meta"]["command"] == "top-ports"
    assert doc["meta"]["rows"] == 2 and doc["meta"]["rows_skipped"] == 0


def test_stdin_matches_path(run, twelve):
    from_path = run("top-ports", str(twelve))
    from_stdin = run("top-ports", "-", stdin_text=twelve.read_text())
    assert from_stdin.code == 0
    assert from_stdin.out == from_path.out


def test_dirty_file_completes_and_reports_skipped(run, dirty):
    r = run("top-ports", str(dirty))
    assert r.code == 0
    assert "3 rows skipped" in r.err
    assert table_rows(r.out)  # some output


# ---------------------------------------------------------------- gaps between the criteria


def test_unknown_port_shows_blank_service_in_table(run, csv_file):
    text = HEADER + (
        "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,44444,tcp,100,1\n"
        "2026-09-14T18:00:01Z,10.0.0.1,203.0.113.9,123,udp,100,1\n"
    )
    r = run("top-ports", str(csv_file(text)))
    rows = {row["port"]: row for row in table_rows(r.out)}
    assert rows["44444/tcp"]["service"] == ""
    assert rows["123/udp"]["service"] == "ntp"
    assert rows["44444/tcp"]["flows"] == "1"  # blank cell did not shift the other columns


def test_same_port_on_tcp_and_udp_are_separate_rows(run, csv_file):
    text = HEADER + (
        "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,53,tcp,100,1\n"
        "2026-09-14T18:00:01Z,10.0.0.1,203.0.113.9,53,udp,100,1\n"
        "2026-09-14T18:00:02Z,10.0.0.1,203.0.113.9,53,udp,100,1\n"
    )
    r = run("top-ports", str(csv_file(text)), "--json")
    assert [(x["dst_port"], x["proto"], x["flows"], x["service"]) for x in r.json()["results"]] == [
        (53, "udp", 2, "dns"),
        (53, "tcp", 1, "dns"),
    ]


def test_equal_flows_on_the_same_port_order_tcp_before_udp(run, csv_file):
    text = HEADER + (
        "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,53,udp,100,1\n"
        "2026-09-14T18:00:01Z,10.0.0.1,203.0.113.9,53,tcp,100,1\n"
    )
    r = run("top-ports", str(csv_file(text)), "--json")
    assert [(x["dst_port"], x["proto"]) for x in r.json()["results"]] == [(53, "tcp"), (53, "udp")]


def test_json_meta_carries_the_icmp_count(run, twelve):
    r = run("top-ports", str(twelve), "--json")
    assert r.json()["meta"]["flows_ignored_icmp"] == 1
    r = run("top-ports", str(twelve), "--proto", "tcp", "--json")
    assert r.json()["meta"]["flows_ignored_icmp"] == 1


def test_proto_icmp_is_a_usage_error(run, twelve):
    r = run("top-ports", str(twelve), "--proto", "icmp")
    assert r.code == 1
    assert r.out == ""


def test_clean_run_reports_zero_icmp_ignored(run, dirty):
    r = run("top-ports", str(dirty))
    assert "0 icmp flows ignored" in r.err
    assert "3 rows skipped" in r.err


def test_header_only_table_is_just_the_header_line(run, csv_file):
    r = run("top-ports", str(csv_file(HEADER)))
    assert r.code == 0
    assert r.out.splitlines() == ["port  service  flows  bytes"]


def test_table_is_plain_ascii_with_human_bytes(run, csv_file):
    text = HEADER + "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,tcp,1200000000,1\n"
    r = run("top-ports", str(csv_file(text)))
    assert not ANSI.search(r.out) and r.out.isascii()
    assert "1.2 GB" in r.out


def test_default_limit_is_twenty(run, csv_file):
    rows = "".join(f"2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,{2000 + i},tcp,1,1\n" for i in range(25))
    r = run("top-ports", str(csv_file(HEADER + rows)), "--json")
    assert len(r.json()["results"]) == 20


def test_bad_header_exits_2(run, csv_file):
    r = run("top-ports", str(csv_file("time,src,dst\n1,2,3\n")))
    assert r.code == 2 and r.out == "" and "Traceback" not in r.err


def test_service_table_covers_common_triage_ports(run, csv_file):
    # Through the CLI: the table is built in, keyed by protocol, and knows the ports analysts hit daily.
    cases = [
        (5353, "udp", "mdns"),
        (5355, "udp", "llmnr"),
        (1900, "udp", "ssdp"),
        (3478, "udp", "stun"),
        (1080, "tcp", "socks"),
        (4444, "tcp", "metasploit"),
        (9001, "tcp", "tor-orport"),
        (11211, "tcp", "memcached"),
        (2375, "tcp", "docker"),
        (6443, "tcp", "kubernetes"),
        (623, "udp", "ipmi"),
        (162, "udp", "snmptrap"),
        (1813, "udp", "radius-acct"),
        (5061, "tcp", "sips"),
        (853, "udp", "dns-over-quic"),
        (853, "tcp", "dns-over-tls"),
        (8888, "tcp", "http-alt"),
        (44444, "tcp", None),
    ]
    text = HEADER + "".join(
        f"2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,{port},{proto},100,1\n" for port, proto, _ in cases
    )
    r = run("top-ports", str(csv_file(text)), "--json", "--limit", "50")
    got = {(x["dst_port"], x["proto"]): x["service"] for x in r.json()["results"]}
    assert got == {(port, proto): name for port, proto, name in cases}
