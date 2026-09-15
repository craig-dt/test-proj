"""beacons: rank Tuples of Outbound flows by Beacon score (PRD 6.4, ADR 0001, issue #14).

Two passes over the path, so stdin is refused. Pass 1 (`count_tuples`) keeps a flow count per Tuple, the
set of Internal hosts that source at least one Outbound flow (the Prevalence denominator) and the file
span. Nothing in pass 1 grows with distinct source-destination pairs. Pass 2 (`accumulate`) keeps a
`TupleAccumulator` only for Tuples whose count meets `--min-flows`, and per-destination Internal-host sets
only for those Tuples' destinations. Interval and byte-size statistics are the accumulator's 1000-element
reservoir samples (PRD 10).

Order matters only within a Tuple: a flow earlier than the previous flow of its own Tuple is an
Out-of-order row, dropped from that Tuple's statistics and counted. The count goes to stderr only when it
is non-zero (a heavily shuffled file scores on a fraction of its data; that line is the warning) and always
to `meta.rows_out_of_order`. The `flows` column is the accepted count, and the `--min-flows` gate is applied
to that count as well as to the pass-1 count, so a Tuple that lost rows to ordering never scores on fewer
flows than the gate allows.

No Tuple is ever labelled a beacon; the ranked score is the whole verdict.
"""

from __future__ import annotations

import argparse
import heapq
import ipaddress
import sys
from collections.abc import Iterable
from functools import lru_cache
from typing import Any, NamedTuple

from flowtest.beacon import (
    PREVALENCE_MIN_HOSTS,
    TupleAccumulator,
    adjust_for_prevalence,
    score_state,
)
from flowtest.options import add_common, build_meta, positive_int
from flowtest.reader import InputError, ReadStats, ip_sort_key, read_flows
from flowtest.render import Column, emit, fmt_int

NAME = "beacons"
DEFAULT_MIN_FLOWS = 10
# RFC 1918, IPv4 loopback and link-local, IPv6 unique-local, loopback and link-local (CONTEXT.md).
DEFAULT_INTERNAL = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "fc00::/7",
    "::1/128",
    "fe80::/10",
)

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
TupleKey = tuple[str, str, int, str]  # (source, destination, destination port, protocol)


def fmt_score(value: float) -> str:
    return f"{value:.3f}"


def fmt_seconds(value: float) -> str:
    """Whole seconds stay whole; an even-count sample median can end in .5."""
    return str(int(value)) if value == int(value) else f"{value:.1f}"


COLUMNS = [
    Column("src_ip", "src_ip"),
    Column("dst_ip", "dst_ip"),
    Column("port", "port_proto"),
    Column("flows", "flows", "r", fmt_int),
    Column("median_s", "median_interval_s", "r", fmt_seconds),
    Column("interval", "interval_score", "r", fmt_score),
    Column("size", "size_score", "r", fmt_score),
    Column("histogram", "histogram_score", "r", fmt_score),
    Column("duration", "duration_score", "r", fmt_score),
    Column("prevalence", "prevalence_label", "r"),
    Column("score", "score", "r", fmt_score),
]
TABLE_ONLY = ("port_proto", "prevalence_label")


def cidr(raw: str) -> Network:
    try:
        return ipaddress.ip_network(raw.strip(), strict=False)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{raw!r} is not an IPv4 or IPv6 CIDR network") from None


class HostClassifier:
    """Internal-or-not for canonical address strings, against a fixed list of networks.

    The answer is memoised per address with a bounded cache: a 10 M-row file names far more distinct
    destinations than sources, and the cache must not become a second copy of them.
    """

    def __init__(self, networks: Iterable[str | Network]):
        self._networks = tuple(
            net if isinstance(net, ipaddress._BaseNetwork) else ipaddress.ip_network(net) for net in networks
        )
        self.is_internal = lru_cache(maxsize=1 << 16)(self._classify)

    def _classify(self, addr: str) -> bool:
        ip = ipaddress.ip_address(addr)
        return any(ip in net for net in self._networks if net.version == ip.version)


class PassOne(NamedTuple):
    """Everything pass 1 leaves behind. Deliberately nothing per destination or per pair."""

    counts: dict[TupleKey, int]
    internal_hosts: set[str]
    file_first: int | None
    file_last: int | None
    stats: ReadStats


class Scored(NamedTuple):
    key: TupleKey
    flows: int
    median_interval: float
    interval: float
    size: float
    histogram: float
    duration: float
    hosts_to_dst: int
    score: float


def count_tuples(path: str, hosts: HostClassifier) -> PassOne:
    """Pass 1: flow count per Outbound Tuple, the Prevalence denominator and the file span."""
    counts: dict[TupleKey, int] = {}
    internal: set[str] = set()
    first = last = None
    is_internal = hosts.is_internal
    with read_flows(path) as stream:
        for flow in stream:
            ts = flow.ts
            if first is None:
                first = last = ts
            elif ts < first:
                first = ts
            elif ts > last:
                last = ts
            if not is_internal(flow.src_ip) or is_internal(flow.dst_ip):
                continue
            key = (flow.src_ip, flow.dst_ip, flow.dst_port, flow.proto)
            counts[key] = counts.get(key, 0) + 1
            internal.add(flow.src_ip)
        return PassOne(counts, internal, first, last, stream.stats)


def accumulate(
    path: str, hosts: HostClassifier, pass_one: PassOne, min_flows: int
) -> tuple[dict[TupleKey, TupleAccumulator], dict[str, set[str]], int, ReadStats]:
    """Pass 2: full state for gate candidates, Internal-host sets for their destinations only.

    Returns the accumulators, the per-destination host sets, the Out-of-order row count and the read
    stats of this pass.
    """
    first, last = pass_one.file_first, pass_one.file_last
    if first is None or last is None:  # no valid rows: nothing can be a candidate, no second read
        return {}, {}, 0, pass_one.stats
    accs = {key: TupleAccumulator(key, first, last) for key, n in pass_one.counts.items() if n >= min_flows}
    pass_one.counts.clear()  # the largest pass-1 structure; pass 2 must not pay for it twice
    hosts_to_dst: dict[str, set[str]] = {key[1]: set() for key in accs}
    out_of_order = 0
    is_internal = hosts.is_internal
    with read_flows(path) as stream:
        for flow in stream:
            ts = flow.ts
            if ts < first or ts > last:
                raise InputError(f"{path} changed while being read; run again")
            dst = flow.dst_ip
            sources = hosts_to_dst.get(dst)
            if sources is None:
                continue  # not a destination of any candidate Tuple: nothing to record
            src = flow.src_ip
            if not is_internal(src) or is_internal(dst):
                continue
            sources.add(src)
            acc = accs.get((src, dst, flow.dst_port, flow.proto))
            if acc is None:
                continue
            if acc.last is not None and ts < acc.last:
                out_of_order += 1
                continue
            acc.add(ts, flow.bytes)
        return accs, hosts_to_dst, out_of_order, stream.stats


def score_all(
    accs: dict[TupleKey, TupleAccumulator],
    hosts_to_dst: dict[str, set[str]],
    internal_hosts_total: int,
    min_flows: int,
) -> list[Scored]:
    scored = []
    for key, acc in accs.items():
        if acc.flows < min_flows:
            continue
        result = score_state(acc.state())
        if result is None:
            continue
        hosts = len(hosts_to_dst[key[1]])
        adjusted = adjust_for_prevalence(
            result.score, hosts_to_dst=hosts, internal_hosts_total=internal_hosts_total
        )
        scored.append(
            Scored(
                key,
                acc.flows,
                result.median_interval,
                result.interval,
                result.size,
                result.histogram,
                result.duration,
                hosts,
                adjusted.score,
            )
        )
    return scored


def _rank_key(item: Scored) -> tuple:
    src, dst, port, proto = item.key
    return (-item.score, ip_sort_key(src), ip_sort_key(dst), port, proto)


def _row(item: Scored, internal_hosts_total: int) -> dict[str, Any]:
    src, dst, port, proto = item.key
    return {
        "src_ip": src,
        "dst_ip": dst,
        "dst_port": port,
        "proto": proto,
        "port_proto": f"{port}/{proto}",
        "flows": item.flows,
        "median_interval_s": item.median_interval,
        "interval_score": item.interval,
        "size_score": item.size,
        "histogram_score": item.histogram,
        "duration_score": item.duration,
        "hosts_to_dst": item.hosts_to_dst,
        "prevalence": round(item.hosts_to_dst / internal_hosts_total, 4),
        "prevalence_label": f"{item.hosts_to_dst}/{internal_hosts_total}",
        "score": item.score,
    }


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        NAME,
        help="rank (source, destination, port, protocol) Tuples of Outbound flows by Beacon score",
        description=(
            "Rank Tuples of Outbound flows (Internal source, External destination) by RITA v5-style Beacon "
            "score: interval regularity, byte-size consistency, hourly-histogram shape and duration coverage, "
            "each 0 to 1 and averaged, then adjusted by Prevalence (+0.15 when at most 2% of Internal hosts "
            "reach the destination, -0.15 at 50% or more; only when at least 10 Internal hosts source Outbound "
            "flows). Reads the file twice, so it needs a path and does not accept - for stdin."
        ),
        epilog=(
            "A short burst scores lower than the same schedule kept up all file long: the histogram and "
            "duration sub-scores need coverage of the file span. Rows only need to be in order within a "
            "Tuple; a row earlier than its Tuple's previous row is dropped and counted on stderr. Interval and "
            "size statistics come from a 1000-flow reservoir sample per Tuple (exact at or below 1000 flows). "
            "No Tuple is ever labelled a beacon; the score is the whole verdict."
        ),
    )
    add_common(p, allow_stdin=False)
    p.add_argument(
        "--min-flows",
        type=positive_int,
        default=DEFAULT_MIN_FLOWS,
        metavar="N",
        help=f"flows a Tuple needs before it is scored (default {DEFAULT_MIN_FLOWS}); it also needs 3 non-zero "
        "Intervals",
    )
    p.add_argument(
        "--internal",
        type=cidr,
        action="append",
        metavar="CIDR",
        help="an Internal network; repeatable, IPv4 or IPv6; replaces the default list (RFC 1918, loopback, "
        "link-local, IPv6 unique-local)",
    )
    p.set_defaults(func=run)


def run(args: argparse.Namespace, start: float) -> int:
    if args.file == "-":
        sys.stderr.write(
            "flowtest beacons: error: beacons needs a file path, not - (stdin): it reads the input twice\n"
        )
        return 1
    hosts = HostClassifier(args.internal or DEFAULT_INTERNAL)
    pass_one = count_tuples(args.file, hosts)
    accs, hosts_to_dst, out_of_order, stats = accumulate(args.file, hosts, pass_one, args.min_flows)
    total = len(pass_one.internal_hosts)
    scored = score_all(accs, hosts_to_dst, total, args.min_flows)
    ranked = heapq.nsmallest(args.limit, scored, key=_rank_key)
    results = [_row(item, total) for item in ranked]

    meta = build_meta(NAME, args.file, stats, start)
    meta["rows_out_of_order"] = out_of_order
    meta["internal_hosts_total"] = total
    meta["prevalence_applied"] = total >= PREVALENCE_MIN_HOSTS
    emit(
        as_json=args.json,
        columns=COLUMNS,
        results=[{k: v for k, v in r.items() if k not in TABLE_ONLY} for r in results]
        if args.json
        else results,
        meta=meta,
        stats=stats,
        no_color=args.no_color,
    )
    if out_of_order:
        sys.stderr.write(f"{out_of_order} rows out of order (dropped from beacon scoring)\n")
    if total < PREVALENCE_MIN_HOSTS:
        sys.stderr.write(
            f"prevalence adjustment skipped: {total} internal hosts seen (fewer than {PREVALENCE_MIN_HOSTS})\n"
        )
    return 0
