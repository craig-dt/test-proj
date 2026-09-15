"""Reader contract (PRD 6.1): timestamp forms, field rules, skipped rows. Exercised through the public
reader API because top-talkers does not surface timestamps."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from conftest import HEADER


def epoch(iso: str) -> int:
    """Expected whole-second UTC epoch for an ISO string, computed independently of the reader."""
    dt = datetime.fromisoformat(iso)
    return int((dt if dt.tzinfo else dt.replace(tzinfo=UTC)).timestamp())


def read_all(path):
    from flowtest.reader import read_flows

    with read_flows(str(path)) as stream:
        flows = list(stream)
        return flows, stream.stats


def test_epoch_seconds_and_iso_in_same_file(csv_file):
    want = epoch("2026-09-14T17:00:00+00:00")
    text = HEADER + (
        f"{want},10.0.0.1,203.0.113.9,443,tcp,1,1\n"
        "2026-09-14T17:00:00Z,10.0.0.1,203.0.113.9,443,tcp,1,1\n"
        f"{want}.75,10.0.0.1,203.0.113.9,443,tcp,1,1\n"
    )
    flows, stats = read_all(csv_file(text))
    assert [f.ts for f in flows] == [want, want, want]
    assert stats.skipped == 0


def test_offset_is_converted_to_utc_and_space_separator_accepted(csv_file):
    text = HEADER + "2026-09-14 18:04:11+02:00,10.0.0.1,203.0.113.9,443,tcp,1,1\n"
    flows, _ = read_all(csv_file(text))
    assert flows[0].ts == epoch("2026-09-14T16:04:11+00:00")


def test_no_zone_means_utc(csv_file):
    text = HEADER + "2026-09-14T16:04:11,10.0.0.1,203.0.113.9,443,tcp,1,1\n"
    flows, _ = read_all(csv_file(text))
    assert flows[0].ts == epoch("2026-09-14T16:04:11+00:00")


def test_epoch_milliseconds_is_skipped(csv_file):
    text = HEADER + "1757873051000,10.0.0.1,203.0.113.9,443,tcp,1,1\n"
    flows, stats = read_all(csv_file(text))
    assert flows == [] and stats.skipped == 1


def test_icmp_with_empty_port_is_not_skipped(csv_file):
    text = HEADER + "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,,ICMP,1,1\n"
    flows, stats = read_all(csv_file(text))
    assert stats.skipped == 0
    assert flows[0].proto == "icmp" and flows[0].dst_port == 0


def test_tcp_with_empty_port_is_skipped(csv_file):
    text = HEADER + "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,,tcp,1,1\n"
    _, stats = read_all(csv_file(text))
    assert stats.skipped == 1


@pytest.mark.parametrize(
    "row",
    [
        "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,gre,1,1",  # bad proto
        "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,70000,tcp,1,1",  # port out of range
        "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,tcp,1.5,1",  # non-integer bytes
        "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,tcp,1,-1",  # negative packets
        "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,tcp,1",  # too few fields
        "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,tcp,1,1,extra",  # too many fields
        "1999-12-31T23:59:59Z,10.0.0.1,203.0.113.9,443,tcp,1,1",  # before 2000
    ],
)
def test_malformed_rows_are_skipped(csv_file, row):
    _, stats = read_all(csv_file(HEADER + row + "\n"))
    assert stats.skipped == 1 and stats.rows == 1


def test_ipv6_accepted(csv_file):
    text = HEADER + "2026-09-14T18:00:00Z,fd00::1,2001:db8::9,443,tcp,1,1\n"
    flows, stats = read_all(csv_file(text))
    assert stats.skipped == 0 and flows[0].src_ip == "fd00::1"


def test_oversized_field_is_a_skipped_row_and_reading_continues(csv_file):
    # A field beyond csv.field_size_limit() makes the csv module reject the record (PRD 6.1).
    import csv

    huge = "x" * (csv.field_size_limit() + 10)
    text = HEADER + (
        "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,tcp,1,1\n"
        f"{huge},10.0.0.1,203.0.113.9,443,tcp,1,1\n"
        "2026-09-14T18:00:02Z,10.0.0.2,203.0.113.9,443,tcp,1,1\n"
    )
    flows, stats = read_all(csv_file(text))
    assert [f.src_ip for f in flows] == ["10.0.0.1", "10.0.0.2"]
    assert stats.skipped == 1 and stats.rows == 3


def test_stray_quote_costs_one_row_not_the_rest_of_the_file(csv_file):
    # Review F1: with quoting enabled a lone quote swallowed every following line. Policy: quoting off.
    good = "2026-09-14T18:00:0{i}Z,10.0.0.{i},203.0.113.9,443,tcp,1,1\n"
    text = (
        HEADER
        + good.format(i=1)
        + '"oops,10.0.0.1,203.0.113.9,443,tcp,1,1\n'
        + "".join(good.format(i=i) for i in range(2, 6))
    )
    flows, stats = read_all(csv_file(text))
    assert len(flows) == 5 and stats.skipped == 1 and stats.rows == 6


def test_fully_quoted_export_is_accepted(csv_file):
    text = HEADER + '"2026-09-14T18:00:00Z","10.0.0.1","203.0.113.9","443","tcp","1","1"\n'
    flows, stats = read_all(csv_file(text))
    assert stats.skipped == 0 and flows[0].src_ip == "10.0.0.1" and flows[0].dst_port == 443


def test_quoted_header_is_accepted(csv_file):
    text = '"ts","src_ip","dst_ip","dst_port","proto","bytes","packets"\n' + (
        "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,tcp,1,1\n"
    )
    flows, _ = read_all(csv_file(text))
    assert len(flows) == 1


def test_scoped_ipv6_is_a_skipped_row(csv_file):
    # Security finding: a scope id is echoed verbatim by ipaddress and can carry terminal escapes.
    text = HEADER + "2026-09-14T18:00:00Z,fe80::1%\x1b[2Kevil,2001:db8::9,443,tcp,1,1\n"
    flows, stats = read_all(csv_file(text))
    assert flows == [] and stats.skipped == 1


def test_ipv4_mapped_ipv6_is_the_ipv4_host(csv_file):
    text = HEADER + "2026-09-14T18:00:00Z,::ffff:10.0.0.1,203.0.113.9,443,tcp,1,1\n"
    flows, _ = read_all(csv_file(text))
    assert flows[0].src_ip == "10.0.0.1"


@pytest.mark.parametrize(
    "row",
    [
        "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,+5,tcp,1,1",  # signed port
        "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,tcp,1_000,1",  # underscore digits
        "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,tcp,１２,1",  # full-width digits
        "1e9,10.0.0.1,203.0.113.9,443,tcp,1,1",  # exponent epoch
        "1_757_873_000,10.0.0.1,203.0.113.9,443,tcp,1,1",  # underscore epoch
        "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,tcp,+100,1",  # signed bytes
    ],
)
def test_only_plain_ascii_digits_are_numbers(csv_file, row):
    _, stats = read_all(csv_file(HEADER + row + "\n"))
    assert stats.skipped == 1


@pytest.mark.parametrize("column", ["dst_port", "bytes", "packets", "ts"])
def test_absurdly_long_numbers_are_skipped_not_fatal(csv_file, column):
    # Re-review: int() refuses > 4300 digits with ValueError; must be a Skipped row, never a traceback.
    # Also pins the 20-digit cap: anything longer is not a number this contract accepts.
    fields = {
        "ts": "2026-09-14T18:00:00Z",
        "src_ip": "10.0.0.1",
        "dst_ip": "203.0.113.9",
        "dst_port": "443",
        "proto": "tcp",
        "bytes": "1",
        "packets": "1",
    }
    fields[column] = "9" * 5000
    row = ",".join(fields.values())
    _, stats = read_all(csv_file(HEADER + row + "\n"))
    assert stats.skipped == 1 and stats.rows == 1


def test_twenty_digit_numbers_are_the_limit(csv_file):
    ok = HEADER + f"2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,tcp,{'9' * 20},1\n"
    too_long = HEADER + f"2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,tcp,{'9' * 21},1\n"
    assert read_all(csv_file(ok))[1].skipped == 0
    assert read_all(csv_file(too_long, name="b.csv"))[1].skipped == 1


def test_icmp_port_is_normalised_to_zero(csv_file):
    text = HEADER + "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,icmp,1,1\n"
    flows, stats = read_all(csv_file(text))
    assert stats.skipped == 0 and flows[0].dst_port == 0


@pytest.mark.parametrize(
    ("ts", "ok"),
    [
        ("946684799", False),  # 1999-12-31T23:59:59Z
        ("946684800", True),  # 2000-01-01T00:00:00Z
        ("4102444799", True),  # 2099-12-31T23:59:59Z
        ("4102444800", False),  # 2100-01-01T00:00:00Z
    ],
)
def test_timestamp_range_boundaries(csv_file, ts, ok):
    flows, stats = read_all(csv_file(HEADER + f"{ts},10.0.0.1,203.0.113.9,443,tcp,1,1\n"))
    assert (stats.skipped == 0) is ok
    if ok:
        assert flows[0].ts == int(ts)


@pytest.mark.parametrize(("port", "ok"), [("65535", True), ("65536", False), ("0", True)])
def test_port_boundaries(csv_file, port, ok):
    _, stats = read_all(csv_file(HEADER + f"2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,{port},tcp,1,1\n"))
    assert (stats.skipped == 0) is ok


def test_padded_fields_are_accepted(csv_file):
    text = HEADER + " 2026-09-14T18:00:00Z , 10.0.0.1 , 203.0.113.9 , 443 , TCP , 1 , 1 \n"
    flows, stats = read_all(csv_file(text))
    assert stats.skipped == 0 and flows[0].dst_port == 443


def test_skipped_row_records_physical_line_number(csv_file):
    text = HEADER + (
        "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,tcp,1,1\n"
        "2026-09-14T18:00:01Z,10.0.0.1,203.0.113.9,443,tcp,1,1\n"
        "bad,row\n"
    )
    _, stats = read_all(csv_file(text))
    assert stats.first_skipped_line == 4
