"""Shape of the seeded synthetic generator (issue #15, PRD section 10 reference input), checked at small
scale through the script's public interface (CLI arguments, files it writes) and the flowtest reader."""

from __future__ import annotations

import importlib.util
import json
import statistics
import subprocess
import sys
import time
from collections import defaultdict
from itertools import islice, pairwise
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "gen_flows.py"
ROWS = 100_000
SEED = 7
HOSTS = 500
BEACONS = 5
SPAN = 24 * 3600


def load_script():
    spec = importlib.util.spec_from_file_location("gen_flows", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module  # standard recipe; dataclasses look the module up by name
    spec.loader.exec_module(module)
    return module


def run_main(module, *argv: str) -> int:
    try:
        return int(module.main(list(argv)))
    except SystemExit as exc:
        return int(exc.code or 0)


def read_all(path: Path):
    from flowtest.reader import read_flows

    with read_flows(str(path)) as stream:
        flows = list(stream)
        return flows, stream.stats


def generate(module, directory: Path, seed: int, rows: int = ROWS, name: str = "synth") -> tuple[Path, Path]:
    out = directory / f"{name}-{seed}.csv"
    side = directory / f"{name}-{seed}.beacons.jsonl"
    code = run_main(
        module, "--rows", str(rows), "--seed", str(seed), "--output", str(out), "--beacons-out", str(side)
    )
    assert code == 0
    return out, side


@pytest.fixture(scope="module")
def gen():
    return load_script()


@pytest.fixture(scope="module")
def synth(gen, tmp_path_factory):
    """One 100 k-row file with defaults, parsed once: (csv path, sidecar path, flows, stats)."""
    out, side = generate(gen, tmp_path_factory.mktemp("synth"), SEED)
    flows, stats = read_all(out)
    return out, side, flows, stats


def planted(side: Path) -> list[dict]:
    return [json.loads(line) for line in side.read_text().splitlines() if line.strip()]


def by_tuple(flows) -> dict[tuple, list]:
    groups: dict[tuple, list] = defaultdict(list)
    for f in flows:
        groups[(f.src_ip, f.dst_ip, f.dst_port, f.proto)].append(f)
    return groups


# --- determinism -------------------------------------------------------------------------------------------


def test_same_seed_identical_files_different_seed_differs(gen, tmp_path):
    a_csv, a_side = generate(gen, tmp_path, 11, name="a")
    b_csv, b_side = generate(gen, tmp_path, 11, name="b")
    c_csv, c_side = generate(gen, tmp_path, 12, name="c")
    assert a_csv.read_bytes() == b_csv.read_bytes()
    assert a_side.read_bytes() == b_side.read_bytes()
    assert a_csv.read_bytes() != c_csv.read_bytes()
    assert a_side.read_bytes() != c_side.read_bytes()


# --- file contract -----------------------------------------------------------------------------------------


def test_exact_header_and_row_count(synth):
    from flowtest.reader import EXPECTED_HEADER

    out, _, _, stats = synth
    with out.open(encoding="utf-8") as fh:
        first = fh.readline()
    assert first == ",".join(EXPECTED_HEADER) + "\n"
    assert stats.rows == ROWS


def test_valid_rows_in_non_decreasing_ts_over_the_full_span(synth, gen):
    _, _, flows, _ = synth
    ts = [f.ts for f in flows]
    assert all(a <= b for a, b in pairwise(ts))
    assert ts[0] == gen.DEFAULT_START
    assert SPAN - 60 <= ts[-1] - ts[0] <= SPAN


def test_about_a_tenth_of_a_percent_malformed(synth):
    _, _, _, stats = synth
    assert stats.skipped == round(ROWS * 0.001)


def test_malformed_rate_is_a_parameter_and_every_malformed_row_is_really_skipped(gen, tmp_path):
    """A 5 % rate on 60 k rows makes 3 000 Skipped rows of several kinds; every kind must fail the reader
    (an out-of-range port on an ICMP row, for example, would not)."""
    out, side = generate(gen, tmp_path, 3, rows=60_000)
    code = run_main(
        gen, "--rows", "60000", "--seed", "3", "--malformed-rate", "0.05",
        "--output", str(out), "--beacons-out", str(side),
    )  # fmt: skip
    assert code == 0
    from flowtest.reader import parse_row

    bad = []
    with out.open(encoding="utf-8") as fh:
        next(fh)
        for line in fh:
            fields = line.rstrip("\n").split(",")
            if parse_row(fields) is None:
                bad.append(fields)
    kinds = {"columns" if len(f) != 7 else "ts" if not f[0][:4].isdigit() else "other" for f in bad}
    assert len(bad) == 3_000 and len(kinds) == 3


# --- planted beacons ---------------------------------------------------------------------------------------


def test_five_planted_beacons_with_stated_interval_and_jitter(synth):
    _, side, flows, _ = synth
    beacons = planted(side)
    assert len(beacons) == BEACONS
    assert len({b["src_ip"] for b in beacons}) == BEACONS, "each beacon from a distinct Internal host"
    groups = by_tuple(flows)
    by_dst: dict[str, set[str]] = defaultdict(set)
    for f in flows:
        by_dst[f.dst_ip].add(f.src_ip)

    for b in beacons:
        assert 30 <= b["interval_s"] <= 900
        assert 0.05 <= b["jitter"] <= 0.10
        key = (b["src_ip"], b["dst_ip"], b["dst_port"], b["proto"])
        got = groups[key]
        assert by_dst[b["dst_ip"]] == {b["src_ip"]}, "beacon destination contacted by no other host"
        # Malformed rows may knock out a few flows, so allow a small deficit against the sidecar count.
        assert b["flows"] - 5 <= len(got) <= b["flows"]
        intervals = [n.ts - p.ts for p, n in pairwise(got)]
        lo, hi = b["interval_s"] * (1 - b["jitter"]) - 1, b["interval_s"] * (1 + b["jitter"]) + 1
        # A skipped flow doubles one interval; everything else must sit inside the jitter band.
        outside = [i for i in intervals if not lo <= i <= hi]
        assert len(outside) <= b["flows"] - len(got)
        assert abs(statistics.median(intervals) - b["interval_s"]) <= 0.03 * b["interval_s"]
        assert got[0].ts - flows[0].ts <= hi, "beacon starts at the beginning of the span"
        assert flows[-1].ts - got[-1].ts <= 2 * hi, "beacon runs to the end of the span"


def test_beacon_count_and_hosts_are_parameters(gen, tmp_path):
    out, side = generate(gen, tmp_path, 5, rows=120_000)
    code = run_main(
        gen, "--rows", "120000", "--seed", "5", "--hosts", "40", "--beacons", "2",
        "--output", str(out), "--beacons-out", str(side),
    )  # fmt: skip
    assert code == 0
    flows, _ = read_all(out)
    assert len(planted(side)) == 2
    assert len({f.src_ip for f in flows}) == 40


# --- NTP-like Tuple ----------------------------------------------------------------------------------------


def test_one_shared_ntp_destination_hit_by_every_internal_host_every_15_min(synth):
    _, side, flows, _ = synth
    hosts = {f.src_ip for f in flows}
    assert len(hosts) == HOSTS
    by_dst: dict[str, set[str]] = defaultdict(set)
    for f in flows:
        by_dst[f.dst_ip].add(f.src_ip)
    shared = [d for d, srcs in by_dst.items() if srcs == hosts]
    assert len(shared) == 1, "exactly one destination is contacted by every Internal host"
    ntp_dst = shared[0]
    assert ntp_dst not in {b["dst_ip"] for b in planted(side)}

    per_host = defaultdict(list)
    for f in flows:
        if f.dst_ip == ntp_dst:
            assert f.dst_port == 123 and f.proto == "udp"
            per_host[f.src_ip].append(f.ts)
    for ts in per_host.values():
        intervals = {n - p for p, n in pairwise(ts)}
        assert intervals <= {900, 1800}, "every 15 min; a malformed row may skip one"
        assert SPAN // 900 - 2 <= len(ts) <= SPAN // 900


# --- browser-like noise ------------------------------------------------------------------------------------


def test_noise_is_many_short_lived_tuples_to_many_destinations(synth):
    _, side, flows, _ = synth
    beacon_dsts = {b["dst_ip"] for b in planted(side)}
    hosts = {f.src_ip for f in flows}
    by_dst: dict[str, set[str]] = defaultdict(set)
    for f in flows:
        by_dst[f.dst_ip].add(f.src_ip)
    ntp_dst = next(d for d, s in by_dst.items() if s == hosts)
    noise = [f for f in flows if f.dst_ip not in beacon_dsts and f.dst_ip != ntp_dst]
    groups = by_tuple(noise)

    # 10 M rows carry about 1.5 M Tuples: roughly one Tuple per 6.6 noise flows at any scale.
    expected = len(noise) / 6.6
    assert 0.75 * expected <= len(groups) <= 1.25 * expected
    assert len({f.dst_ip for f in noise}) >= 0.5 * len(groups), "many destinations"
    spans = [g[-1].ts - g[0].ts for g in groups.values() if len(g) > 1]
    assert statistics.median(spans) < 900, "short-lived"
    sizes = {f.bytes for f in noise}
    assert len(sizes) > 1000, "varied sizes"
    intervals = [n.ts - p.ts for g in groups.values() for p, n in pairwise(g)]
    assert statistics.pstdev(intervals) > 5, "irregular intervals"
    assert all(f.dst_port <= 65535 for f in noise)


# --- streaming, CLI ----------------------------------------------------------------------------------------


def test_rows_stream_lazily_without_materialising_the_file(gen):
    params = gen.Params(rows=10**9, seed=1)
    t0 = time.perf_counter()
    lines = list(islice(gen.iter_lines(params), 1000))
    assert time.perf_counter() - t0 < 5
    assert len(lines) == 1000 and lines[0].startswith("ts,")


def test_defaults_write_csv_to_stdout_and_beacons_to_stderr(gen, capsys):
    assert run_main(gen, "--rows", "60000", "--seed", "2") == 0
    captured = capsys.readouterr()
    assert captured.out.startswith("ts,src_ip,dst_ip,dst_port,proto,bytes,packets\n")
    assert captured.out.count("\n") == 60_001
    assert len([json.loads(line) for line in captured.err.splitlines() if line.strip()]) == BEACONS


def test_too_few_rows_for_the_shape_is_a_usage_error(gen, capsys):
    code = run_main(gen, "--rows", "10", "--seed", "1")
    assert code == 1
    assert "rows" in capsys.readouterr().err


def test_help_documents_every_parameter_and_runs_standalone():
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"], capture_output=True, text=True, check=False
    )
    assert proc.returncode == 0
    for flag in ("--rows", "--seed", "--hosts", "--beacons", "--jitter-min", "--jitter-max",
                 "--malformed-rate", "--output", "--beacons-out"):  # fmt: skip
        assert flag in proc.stdout, flag
