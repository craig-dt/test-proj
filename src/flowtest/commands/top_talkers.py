"""top-talkers: rank hosts by bytes, packets or flow count (PRD 6.2)."""

from __future__ import annotations

import argparse
import heapq
from operator import attrgetter

from flowtest.options import add_common, build_meta
from flowtest.reader import ip_sort_key, read_flows
from flowtest.render import Column, emit, fmt_int, human_bytes

NAME = "top-talkers"
MEASURES = {"bytes": 0, "packets": 1, "flows": 2}
COLUMNS = [
    Column("host", "host"),
    Column("bytes", "bytes", "r", human_bytes),
    Column("packets", "packets", "r", fmt_int),
    Column("flows", "flows", "r", fmt_int),
]


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(NAME, help="rank hosts by traffic volume")
    add_common(p)
    p.add_argument("--by", choices=tuple(MEASURES), default="bytes", help="ranking measure (default bytes)")
    p.add_argument("--direction", choices=("src", "dst"), default="src", help="rank sources or destinations")
    p.set_defaults(func=run)


def run(args: argparse.Namespace, start: float) -> int:
    host_of = attrgetter(f"{args.direction}_ip")  # Flow.src_ip or Flow.dst_ip
    totals: dict[str, list[int]] = {}
    with read_flows(args.file) as stream:
        for flow in stream:
            key = host_of(flow)
            t = totals.get(key)
            if t is None:
                totals[key] = [flow.bytes, flow.packets, 1]
            else:
                t[0] += flow.bytes
                t[1] += flow.packets
                t[2] += 1
        stats = stream.stats

    measure = MEASURES[args.by]
    ranked = heapq.nsmallest(args.limit, totals.items(), key=lambda kv: (-kv[1][measure], ip_sort_key(kv[0])))
    results = [{"host": host, "bytes": t[0], "packets": t[1], "flows": t[2]} for host, t in ranked]
    emit(
        as_json=args.json,
        columns=COLUMNS,
        results=results,
        meta=build_meta(NAME, args.file, stats, start),
        stats=stats,
        no_color=args.no_color,
    )
    return 0
