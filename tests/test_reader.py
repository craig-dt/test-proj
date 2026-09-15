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


def test_csv_reader_error_is_a_skipped_row(csv_file):
    # An unterminated quote spanning to EOF makes the csv module raise; that record is skipped.
    text = HEADER + '2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,tcp,1,1\n"unterminated,10.0.0.1\n'
    flows, stats = read_all(csv_file(text))
    assert len(flows) == 1 and stats.skipped == 1


def test_skipped_row_records_physical_line_number(csv_file):
    text = HEADER + (
        "2026-09-14T18:00:00Z,10.0.0.1,203.0.113.9,443,tcp,1,1\n"
        "2026-09-14T18:00:01Z,10.0.0.1,203.0.113.9,443,tcp,1,1\n"
        "bad,row\n"
    )
    _, stats = read_all(csv_file(text))
    assert stats.first_skipped_line == 4
