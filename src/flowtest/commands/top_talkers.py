"""top-talkers: rank hosts or Pairs by bytes, packets or flow count (PRD 6.2)."""

from __future__ import annotations

import argparse
import heapq
from collections.abc import Callable
from operator import attrgetter

from flowtest.options import add_common, build_meta
from flowtest.reader import Flow, ip_sort_key, read_flows
from flowtest.render import Column, emit, fmt_int, human_bytes

NAME = "top-talkers"
MEASURES = {"bytes": 0, "packets": 1, "flows": 2}
DIRECTIONS = ("src", "dst", "pair")
MEASURE_COLUMNS = [
    Column("bytes", "bytes", "r", human_bytes),
    Column("packets", "packets", "r", fmt_int),
    Column("flows", "flows", "r", fmt_int),
]
HOST_COLUMNS = [Column("host", "host"), *MEASURE_COLUMNS]
PAIR_COLUMNS = [Column("src_ip", "src_ip"), Column("dst_ip", "dst_ip"), *MEASURE_COLUMNS]

# A ranking key is one host address (src/dst) or a (source, destination) Pair. Pairs ignore port and
# protocol (CONTEXT.md). Ties break by key in IP address order: source first, then destination.
Key = str | tuple[str, str]


def _pair_key(flow: Flow) -> tuple[str, str]:
    return (flow.src_ip, flow.dst_ip)


def _pair_sort_key(key: tuple[str, str]) -> tuple[tuple[int, int], tuple[int, int]]:
    return (ip_sort_key(key[0]), ip_sort_key(key[1]))


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(NAME, help="rank hosts or (source, destination) pairs by traffic volume")
    add_common(p)
    p.add_argument("--by", choices=tuple(MEASURES), default="bytes", help="ranking measure (default bytes)")
    p.add_argument(
        "--direction",
        choices=DIRECTIONS,
        default="src",
        help=(
            "rank sources (default), destinations, or (source, destination) pairs regardless of port and "
            "protocol; memory grows with the number of distinct pairs"
        ),
    )
    p.set_defaults(func=run)


def run(args: argparse.Namespace, start: float) -> int:
    key_of: Callable[[Flow], Key]
    sort_key: Callable
    if args.direction == "pair":
        key_of, sort_key, columns = _pair_key, _pair_sort_key, PAIR_COLUMNS
    else:
        key_of, sort_key, columns = attrgetter(f"{args.direction}_ip"), ip_sort_key, HOST_COLUMNS

    totals: dict[Key, list[int]] = {}
    with read_flows(args.file) as stream:
        for flow in stream:
            key = key_of(flow)
            t = totals.get(key)
            if t is None:
                totals[key] = [flow.bytes, flow.packets, 1]
            else:
                t[0] += flow.bytes
                t[1] += flow.packets
                t[2] += 1
        stats = stream.stats

    measure = MEASURES[args.by]
    ranked = heapq.nsmallest(args.limit, totals.items(), key=lambda kv: (-kv[1][measure], sort_key(kv[0])))
    results = []
    for key, t in ranked:
        row = {"src_ip": key[0], "dst_ip": key[1]} if isinstance(key, tuple) else {"host": key}
        row.update(bytes=t[0], packets=t[1], flows=t[2])
        results.append(row)
    emit(
        as_json=args.json,
        columns=columns,
        results=results,
        meta=build_meta(NAME, args.file, stats, start),
        stats=stats,
    )
    return 0
