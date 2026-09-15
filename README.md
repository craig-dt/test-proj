# flowtest

Offline triage for a NetFlow-style CSV export, for a SOC analyst with a file and ten minutes. Three commands,
no server, no database, no network access, standard library only:

```sh
uv run flowtest top-talkers flows.csv --by bytes --direction src     # who talks the most
uv run flowtest top-ports   flows.csv --proto tcp                    # which ports are in play
uv run flowtest beacons     flows.csv --min-flows 10 --limit 20      # regular call-outs, ranked by score
```

Add `--json` for one machine-readable object (`results` + `meta`) on stdout. Malformed rows are counted on
stderr and never abort a run. Install with `uv tool install .`; `uv run flowtest --help` documents everything.

Input: a CSV with the header `ts,src_ip,dst_ip,dst_port,proto,bytes,packets` (ISO-8601 or epoch timestamps,
tcp/udp/icmp). One flow is treated as one connection; exports that split or merge connections distort the
interval statistics. `beacons` scores (source, destination, port, protocol) Tuples of internal-to-external
flows with a RITA-inspired formula (four sub-scores plus a prevalence adjustment; see `docs/adr/0001-*.md`).
It is RITA-inspired, not RITA-compatible: RITA groups by host pair and reads Zeek logs. No Tuple is ever
labelled a beacon; the analyst decides.

## Run / test
See `CLAUDE.md` → Commands. Product requirements: `docs/prd.md`; glossary: `CONTEXT.md`.

## Reference input (performance runs)
`scripts/gen_flows.py` (standard library only) writes the PRD section 10 synthetic file: 500 Internal hosts,
about 1.5 M Outbound Tuples, 5 planted beacons (30 s to 15 min, 5 to 10 % jitter, full 24 h), an NTP-like
Tuple from every host every 15 min, browser-like noise, 0.1 % malformed rows, rows in timestamp order,
deterministic per seed. `--help` lists every parameter (rows, seed, hosts, beacons, jitter range, malformed
rate, start, output paths).

```sh
uv run python scripts/gen_flows.py --rows 10000000 --seed 1 --output /tmp/flows.csv --beacons-out /tmp/planted.jsonl
```

The sidecar holds one JSON object per planted beacon (Tuple, interval, jitter, flow count) so a perf run can
check they rank in the top 5. Measured 2026-09-14 on an Apple M3 Max (36 GB, macOS 15.6, Python 3.12.13):
10 M rows in 17.4 s, 46 MB peak RSS, 605 MB on disk (about 60 bytes per row with whole-second ISO timestamps
and IPv4 addresses). The release procedure also runs the about-1 GB stress variant once: `--rows 16500000` (about 2.5 M Tuples); only the memory bound applies to it (PRD 0.5, section 10).

## How work happens here
This repo is built with an agentic pipeline: GitHub issues carry agent briefs; `scripts/agent-run.sh` builds
`ready-for-agent` issues into PRs in isolated worktrees; CI and a fresh-agent review gate every merge.
`docs/status.yaml` is derived (`scripts/status.py`). Domain vocabulary: `CONTEXT.md`; decisions: `docs/adr/`.
