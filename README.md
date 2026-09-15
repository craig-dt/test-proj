# test-proj

FILL_IN: one-paragraph description of what this project does and for whom.

## Run / test
See `CLAUDE.md` → Commands.

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
