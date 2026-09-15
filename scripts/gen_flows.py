#!/usr/bin/env python3
"""Seeded synthetic flow generator: the PRD's reference input (PRD 0.2 section 10, Performance).

Standard library only; runs from a bare checkout::

    python scripts/gen_flows.py --rows 10000000 --seed 1 --output flows.csv --beacons-out planted.jsonl

Writes a valid flowtest CSV (exact header, rows in non-decreasing ``ts``) whose shape at the default
10 M rows is:

* ``--hosts`` Internal hosts (default 500) in 10.0.0.0/8; every one of them is a source.
* ``--beacons`` planted beacons (default 5): each from a distinct Internal host to a destination in
  203.0.113.0/24 that no other host contacts, on 443/tcp, every ``interval`` seconds (drawn per beacon
  from 30 s to 15 min) with per-flow jitter drawn from ``[-j, +j] * interval`` where ``j`` is drawn per
  beacon from ``--jitter-min``..``--jitter-max`` (default 5 % to 10 %), running the full 24 h span.
* An NTP-like Tuple from every Internal host to one shared destination (198.51.100.123, 123/udp) every
  15 min for 24 h.
* Browser-like noise for every remaining row: many short-lived Tuples (about 6.6 flows each, so about
  1.5 M distinct Tuples at 10 M rows) to many random public destinations, irregular intervals, varied
  sizes, mostly 443/tcp with some 80/tcp, 53/udp, high ports and a little ICMP.
* ``--malformed-rate`` of the rows (default 0.1 %) rewritten as Skipped rows of several kinds.

Every row count is scaled by the noise: NTP and beacon rows are fixed by hosts, beacons and span, and
the noise fills the rest, so ``--rows`` is exact. ``--rows`` must at least cover the NTP and beacon rows.

Deterministic for a given seed. Rows stream to ``--output`` (default stdout) without being held in
memory: memory is bounded by the number of noise flows in flight within one Tuple lifetime (a few
minutes of traffic) plus the planted beacon schedules. The planted beacons are written one JSON object
per line (``src_ip, dst_ip, dst_port, proto, interval_s, jitter, flows``) to ``--beacons-out`` (default
stderr) so a perf run can check that they rank in the top 5.

Public interface: ``Params``, ``iter_lines(params)`` (lazy: header line, then one CSV line per row),
``write(params, out, beacons_out)`` and ``main(argv)``.
"""

from __future__ import annotations

import argparse
import heapq
import random
import sys
from collections.abc import Iterator
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import IO, NamedTuple

HEADER = "ts,src_ip,dst_ip,dst_port,proto,bytes,packets"
DEFAULT_START = 1_789_344_000  # 2026-09-14T00:00:00Z
SPAN = 24 * 3600
NTP_DST = "198.51.100.123"  # TEST-NET-2: public, never used by the noise
NTP_INTERVAL = 900
BEACON_NET = "203.0.113."  # TEST-NET-3: public, never used by the noise
BEACON_INTERVAL_RANGE = (30, 900)
NOISE_MEAN_FLOWS = 6.6  # about 1.5 M Tuples per 10 M rows
NOISE_MAX_FLOWS = 60
NOISE_MEAN_GAP = 15.0  # seconds between flows of one noise Tuple
NOISE_MAX_GAP = 120
# Public /8s the noise draws destinations from. Nothing private, loopback, link-local, multicast or
# TEST-NET, so every noise flow is Outbound and never collides with the planted destinations.
NOISE_FIRST_OCTETS = (23, 34, 35, 44, 45, 52, 54, 64, 66, 69, 74, 104, 107, 108, 142, 151, 157, 162, 185, 199)
NOISE_PORTS = ((443, "tcp", 62), (80, "tcp", 12), (53, "udp", 12), (8443, "tcp", 3), (0, "icmp", 1))
MALFORMED_KINDS = 6


class Params(NamedTuple):
    rows: int
    seed: int
    hosts: int = 500
    beacons: int = 5
    jitter_min: float = 0.05
    jitter_max: float = 0.10
    malformed_rate: float = 0.001
    start: int = DEFAULT_START


@dataclass(frozen=True)
class Beacon:
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str
    interval_s: int
    jitter: float
    schedule: tuple[int, ...]  # flow timestamps

    def sidecar(self) -> str:
        return (
            f'{{"src_ip": "{self.src_ip}", "dst_ip": "{self.dst_ip}", "dst_port": {self.dst_port}, '
            f'"proto": "{self.proto}", "interval_s": {self.interval_s}, "jitter": {self.jitter:.3f}, '
            f'"flows": {len(self.schedule)}}}'
        )


class ShapeError(ValueError):
    """The requested parameters cannot produce the shape (for example too few rows)."""


def internal_hosts(n: int) -> list[str]:
    """n distinct addresses in 10.0.0.0/8, host part never .0 or .255."""
    return [f"10.{(i // 254) // 256}.{(i // 254) % 256}.{i % 254 + 1}" for i in range(n)]


def plan_beacons(rng: random.Random, p: Params, hosts: list[str]) -> list[Beacon]:
    sources = rng.sample(hosts, p.beacons)
    beacons = []
    for i, src in enumerate(sources):
        interval = rng.randint(*BEACON_INTERVAL_RANGE)
        jitter = rng.uniform(p.jitter_min, p.jitter_max)
        end = p.start + SPAN
        ts, schedule = p.start + rng.randint(0, interval), []
        while ts < end:
            schedule.append(ts)
            ts += round(interval * (1 + rng.uniform(-jitter, jitter)))
        beacons.append(Beacon(src, f"{BEACON_NET}{10 + i}", 443, "tcp", interval, jitter, tuple(schedule)))
    return beacons


def beacon_rows(rng: random.Random, b: Beacon) -> Iterator[tuple[int, str]]:
    size = rng.randint(400, 1500)
    for ts in b.schedule:
        nbytes = size + rng.randint(-8, 8)
        yield ts, f"{b.src_ip},{b.dst_ip},{b.dst_port},{b.proto},{nbytes},{nbytes // 100 + 1}"


def ntp_rows(rng: random.Random, p: Params, hosts: list[str]) -> Iterator[tuple[int, str]]:
    """Every host every 15 min at its own phase; emitted period by period so the stream is ordered."""
    phased = sorted((rng.randrange(NTP_INTERVAL), h) for h in hosts)
    for period in range(SPAN // NTP_INTERVAL):
        base = p.start + period * NTP_INTERVAL
        for phase, host in phased:
            yield base + phase, f"{host},{NTP_DST},123,udp,76,1"


def noise_rows(rng: random.Random, p: Params, hosts: list[str], budget: int) -> Iterator[tuple[int, str]]:
    """Exactly `budget` flows in short-lived Tuples whose start times are spread over the span.

    Tuples start in proportion to the budget consumed, so the noise always covers the whole 24 h whatever
    the row count. Each new Tuple's flows go on a heap; everything older than the next Tuple start can be
    emitted safely, so the heap only ever holds one Tuple lifetime of traffic.
    """
    pending: list[tuple[int, int, str]] = []
    push, pop = heapq.heappush, heapq.heappop
    ports = [pp for pp in NOISE_PORTS for _ in range(pp[2])]
    octets = NOISE_FIRST_OCTETS
    choice, randint, expovariate, lognormvariate = (
        rng.choice,
        rng.randint,
        rng.expovariate,
        rng.lognormvariate,
    )
    consumed = seq = 0
    last = p.start + SPAN - 1  # a Tuple that starts late is squeezed into the span, never past it
    while consumed < budget:
        start = p.start + (SPAN - 1) * consumed // budget
        while pending and pending[0][0] <= start:
            ts, _, line = pop(pending)
            yield ts, line
        k = min(1 + int(expovariate(1 / (NOISE_MEAN_FLOWS - 1))), NOISE_MAX_FLOWS, budget - consumed)
        src = choice(hosts)
        dst = f"{choice(octets)}.{randint(0, 255)}.{randint(0, 255)}.{randint(1, 254)}"
        port, proto, _ = choice(ports)
        port_text = "" if proto == "icmp" else str(port)
        ts = start
        for _ in range(k):
            nbytes = int(lognormvariate(7.5, 1.6)) + 60
            packets = nbytes // 700 + 1
            seq += 1
            push(pending, (ts, seq, f"{src},{dst},{port_text},{proto},{nbytes},{packets}"))
            ts = min(ts + min(int(expovariate(1 / NOISE_MEAN_GAP)), NOISE_MAX_GAP), last)
        consumed += k
    while pending:
        ts, _, line = pop(pending)
        yield ts, line


def corrupt(kind: int, ts_text: str, tail: str) -> str:
    """Turn a valid row into a Skipped row of one of several kinds, keeping the line count."""
    fields = tail.split(",")
    if kind == 0:
        return f"not-a-timestamp,{tail}"
    if kind == 1:
        fields[0] = "300.0.0." + fields[0].rsplit(".", 1)[-1]  # bad source IP
    elif kind == 2:
        fields[4] = "-" + fields[4]  # negative bytes
    elif kind == 3:
        fields = fields[:-1]  # too few columns
    elif kind == 4:
        fields[3] = "gre"  # unknown protocol
    else:
        fields[2] = "70000"  # port out of range
    return ts_text + "," + ",".join(fields)


def fixed_rows(p: Params) -> int:
    """Rows fixed by hosts and span before the noise fills the rest (excluding the beacon schedules)."""
    return p.hosts * (SPAN // NTP_INTERVAL)


def iter_lines(p: Params) -> Iterator[str]:
    """Header line, then exactly p.rows CSV lines in non-decreasing ts. Lazy."""
    if p.rows <= 0 or p.hosts <= 0 or p.beacons < 0 or not 0 <= p.malformed_rate <= 1:
        raise ShapeError("rows and hosts must be positive, beacons non-negative, malformed rate in [0, 1]")
    if p.beacons > p.hosts:
        raise ShapeError(f"beacons ({p.beacons}) cannot exceed hosts ({p.hosts}): one beacon per host")
    if not 0 <= p.jitter_min <= p.jitter_max < 1:
        raise ShapeError("jitter must satisfy 0 <= jitter-min <= jitter-max < 1")
    rng = random.Random(p.seed)
    hosts = internal_hosts(p.hosts)
    beacons = plan_beacons(rng, p, hosts)
    fixed = fixed_rows(p) + sum(len(b.schedule) for b in beacons)
    if p.rows < fixed:
        raise ShapeError(
            f"rows ({p.rows}) too few for {p.hosts} hosts and {p.beacons} beacons over 24 h: at least {fixed} "
            "rows are NTP and beacon flows; raise --rows or lower --hosts/--beacons"
        )
    yield from _lines(rng, p, hosts, beacons, p.rows - fixed)


def _lines(
    rng: random.Random, p: Params, hosts: list[str], beacons: list[Beacon], budget: int
) -> Iterator[str]:
    bad_rows = set(rng.sample(range(p.rows), round(p.rows * p.malformed_rate)))
    streams = [ntp_rows(random.Random(rng.random()), p, hosts)]
    streams += [beacon_rows(random.Random(rng.random()), b) for b in beacons]
    streams.append(noise_rows(random.Random(rng.random()), p, hosts, budget))
    yield HEADER
    last_ts, ts_text = None, ""
    for index, (ts, tail) in enumerate(heapq.merge(*streams)):
        if ts != last_ts:
            ts_text = datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            last_ts = ts
        if index in bad_rows:
            yield corrupt(index % MALFORMED_KINDS, ts_text, tail)
        else:
            yield f"{ts_text},{tail}"


def planted_beacons(p: Params) -> list[Beacon]:
    """The beacons iter_lines(p) plants, computed from the same seed."""
    rng = random.Random(p.seed)
    return plan_beacons(rng, p, internal_hosts(p.hosts))


def write(p: Params, out: IO[str], beacons_out: IO[str]) -> None:
    for b in planted_beacons(p):
        beacons_out.write(b.sidecar() + "\n")
    beacons_out.flush()
    lines = iter_lines(p)
    chunk: list[str] = []
    for line in lines:
        chunk.append(line)
        if len(chunk) >= 10_000:
            out.write("\n".join(chunk) + "\n")
            chunk.clear()
    if chunk:
        out.write("\n".join(chunk) + "\n")
    out.flush()


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="gen_flows",
        description="Seeded synthetic flowtest CSV: planted beacons, an NTP-like Tuple, browser noise.",
        epilog="Defaults reproduce the PRD reference shape at --rows 10000000 (about 1.5 M Tuples).",
    )
    ap.add_argument(
        "--rows", type=int, default=10_000_000, help="exact number of data rows (default 10000000)"
    )
    ap.add_argument("--seed", type=int, default=1, help="random seed; same seed, same file (default 1)")
    ap.add_argument("--hosts", type=int, default=500, help="Internal hosts in 10.0.0.0/8 (default 500)")
    ap.add_argument(
        "--beacons", type=int, default=5, help="planted beacons, one per distinct host (default 5)"
    )
    ap.add_argument("--jitter-min", type=float, default=0.05, help="lowest per-beacon jitter fraction (0.05)")
    ap.add_argument(
        "--jitter-max", type=float, default=0.10, help="highest per-beacon jitter fraction (0.10)"
    )
    ap.add_argument(
        "--malformed-rate", type=float, default=0.001, help="share of rows made Skipped rows (0.001)"
    )
    ap.add_argument(
        "--start",
        type=int,
        default=DEFAULT_START,
        help="epoch seconds of the first row (2026-09-14T00:00:00Z)",
    )
    ap.add_argument("--output", default="-", help="CSV path, or - for stdout (default -)")
    ap.add_argument(
        "--beacons-out", default="-", help="planted-beacon JSON lines path, or - for stderr (default -)"
    )
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    p = Params(
        rows=args.rows,
        seed=args.seed,
        hosts=args.hosts,
        beacons=args.beacons,
        jitter_min=args.jitter_min,
        jitter_max=args.jitter_max,
        malformed_rate=args.malformed_rate,
        start=args.start,
    )
    try:
        with ExitStack() as stack:
            out = sys.stdout
            if args.output != "-":
                out = stack.enter_context(open(args.output, "w", encoding="utf-8", newline="\n"))
            side = sys.stderr
            if args.beacons_out != "-":
                side = stack.enter_context(open(args.beacons_out, "w", encoding="utf-8"))
            write(p, out, side)
    except ShapeError as exc:
        sys.stderr.write(f"gen_flows: error: {exc}\n")
        return 1
    except OSError as exc:
        sys.stderr.write(f"gen_flows: {exc.filename or ''}: {exc.strerror or exc}\n".replace(": :", ":"))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
