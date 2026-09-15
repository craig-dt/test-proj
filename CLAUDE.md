# Project: test-proj

flowtest: an offline, stdlib-only Python CLI for a SOC analyst holding a NetFlow-style CSV export. Three commands answer who talks most (`top-talkers`), which ports are in play (`top-ports`) and which internal hosts call out on a suspiciously regular schedule (`beacons`, RITA-inspired scoring). Tens of millions of rows, never the whole file in memory.

## Commands
- Install: uv sync
- Test:    uv run pytest -q
- Lint:    uv run ruff check . && uv run ruff format --check .
- Run:     uv run flowtest <top-talkers|top-ports|beacons> <file.csv> [--json] (see `--help`)

## Architecture
- Entry point `flowtest.cli:main`; each command is a module under `flowtest/commands/` registered in `commands/__init__.py`.
- `reader.py` streams Flows one at a time and owns the whole input contract (PRD 6.1); commands never parse CSV.
- `render.py` owns Table/JSON output and colour; every cell is sanitised there.
- `beacon.py` is the pure scoring library (formula, guards, reservoir accumulator); `commands/beacons.py` is the two-pass driver.
- `scripts/gen_flows.py` generates the reference input; `tests/` exercise the public CLI only.

## Agent skills
### Issue tracker
GitHub Issues in this repo via `gh`; milestone = project/feature scope. See `docs/agents/issue-tracker.md`.
### Triage labels
Canonical names, no remapping. See `docs/agents/triage-labels.md`.
### Domain docs
Single-context: `CONTEXT.md` (glossary) + `docs/adr/`. See `docs/agents/domain.md`.

## Conventions
- Test alongside every behaviour (`tdd` skill); tests exercise public interfaces, never internals.
- Small functions; type hints on public interfaces; config via environment.
- Never call external APIs in tests — mock at the boundary.

## Guardrails (mechanical — see .claude/settings.json and branch protection)
- Commits on `main` are blocked. Destructive git is denied. `.env` is unreadable.
- The Stop hook refuses to end a session with red tests or lint errors when code changed.
- Nothing merges without CI + a fresh review.
