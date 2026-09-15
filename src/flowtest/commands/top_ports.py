"""top-ports: rank destination ports by Flow count with total bytes alongside (PRD 6.3).

tcp and udp are separate rows (443/tcp, 53/udp). icmp Flows have no port: they are ignored and counted,
and stderr reports the count on every run, alongside the skipped-row summary.
"""

from __future__ import annotations

import argparse
import heapq
import sys

from flowtest.options import add_common, build_meta
from flowtest.reader import read_flows
from flowtest.render import Column, emit, fmt_int, human_bytes
from flowtest.services import service_name

NAME = "top-ports"
PROTOS = ("tcp", "udp")
COLUMNS = [
    Column("port", "port_proto"),
    Column("service", "service", "l", lambda s: s or ""),
    Column("flows", "flows", "r", fmt_int),
    Column("bytes", "bytes", "r", human_bytes),
]


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(NAME, help="rank destination ports by flow count")
    add_common(p)
    p.add_argument("--proto", choices=PROTOS, default=None, help="restrict to one protocol (default both)")
    p.set_defaults(func=run)


def run(args: argparse.Namespace, start: float) -> int:
    wanted = PROTOS if args.proto is None else (args.proto,)
    totals: dict[tuple[int, str], list[int]] = {}  # (port, proto) -> [flows, bytes]
    icmp_ignored = 0
    with read_flows(args.file) as stream:
        for flow in stream:
            if flow.proto == "icmp":
                icmp_ignored += 1
                continue
            if flow.proto not in wanted:
                continue
            key = (flow.dst_port, flow.proto)
            t = totals.get(key)
            if t is None:
                totals[key] = [1, flow.bytes]
            else:
                t[0] += 1
                t[1] += flow.bytes
        stats = stream.stats

    # Most flows first; ties by port ascending, then proto so the order is deterministic.
    ranked = heapq.nsmallest(args.limit, totals.items(), key=lambda kv: (-kv[1][0], kv[0]))
    results = [
        {
            "port": port,
            "proto": proto,
            "port_proto": f"{port}/{proto}",
            "service": service_name(port, proto),
            "flows": flows,
            "bytes": nbytes,
        }
        for (port, proto), (flows, nbytes) in ranked
    ]
    emit(
        as_json=args.json,
        columns=COLUMNS,
        results=[_json_row(r) for r in results] if args.json else results,
        meta=build_meta(NAME, args.file, stats, start),
        stats=stats,
        no_color=args.no_color,
    )
    sys.stderr.write(f"{icmp_ignored} icmp flows ignored\n")
    return 0


def _json_row(row: dict) -> dict:
    """JSON carries raw fields (port as an integer, proto separately); the joined label is Table-only."""
    return {k: v for k, v in row.items() if k != "port_proto"}
