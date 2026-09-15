"""top-talkers: rank hosts or Pairs by bytes, packets or flow count (PRD 6.2)."""

from __future__ import annotations

import argparse
import heapq
from collections.abc import Callable
from dataclasses import dataclass
from operator import attrgetter
from typing import Any

from flowtest.options import add_common, build_meta
from flowtest.reader import Flow, ip_sort_key, read_flows
from flowtest.render import Column, emit, fmt_int, human_bytes

NAME = "top-talkers"
MEASURES = {"bytes": 0, "packets": 1, "flows": 2}
MEASURE_COLUMNS = [
    Column("bytes", "bytes", "r", human_bytes),
    Column("packets", "packets", "r", fmt_int),
    Column("flows", "flows", "r", fmt_int),
]

# A ranking key is one host address (src/dst) or a (source, destination) Pair. Pairs ignore port and
# protocol (CONTEXT.md) and are directed: A->B and B->A are separate Pairs. Ties break by key in IP
# address order: source first, then destination.
Key = str | tuple[str, str]


@dataclass(frozen=True)
class Direction:
    """Everything that differs between ranking sources, destinations and Pairs, in one place."""

    key_of: Callable[[Flow], Key]
    sort_key: Callable[[Key], Any]
    columns: list[Column]
    row_of: Callable[[Key], dict[str, Any]]


def _host_direction(attr: str) -> Direction:
    return Direction(
        key_of=attrgetter(attr),
        sort_key=ip_sort_key,
        columns=[Column("host", "host"), *MEASURE_COLUMNS],
        row_of=lambda key: {"host": key},
    )


DIRECTIONS: dict[str, Direction] = {
    "src": _host_direction("src_ip"),
    "dst": _host_direction("dst_ip"),
    "pair": Direction(
        key_of=lambda flow: (flow.src_ip, flow.dst_ip),
        sort_key=lambda key: (ip_sort_key(key[0]), ip_sort_key(key[1])),
        columns=[Column("src_ip", "src_ip"), Column("dst_ip", "dst_ip"), *MEASURE_COLUMNS],
        row_of=lambda key: {"src_ip": key[0], "dst_ip": key[1]},
    ),
}


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(NAME, help="rank hosts or (source, destination) pairs by traffic volume")
    add_common(p)
    p.add_argument("--by", choices=tuple(MEASURES), default="bytes", help="ranking measure (default bytes)")
    p.add_argument(
        "--direction",
        choices=tuple(DIRECTIONS),
        default="src",
        help=(
            "rank sources (default), destinations, or (source, destination) pairs regardless of port and "
            "protocol (directed: A->B and B->A are separate rows); memory grows with the number of "
            "distinct pairs"
        ),
    )
    p.set_defaults(func=run)


def run(args: argparse.Namespace, start: float) -> int:
    direction = DIRECTIONS[args.direction]
    key_of, sort_key = direction.key_of, direction.sort_key

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
        row = direction.row_of(key)
        row.update(bytes=t[0], packets=t[1], flows=t[2])
        results.append(row)
    emit(
        as_json=args.json,
        columns=direction.columns,
        results=results,
        meta=build_meta(NAME, args.file, stats, start),
        stats=stats,
        no_color=args.no_color,
    )
    return 0
