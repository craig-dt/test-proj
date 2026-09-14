# Project: test-proj

FILL_IN: one-paragraph description of what this project does and for whom.

## Commands
- Install: uv sync
- Test:    uv run pytest -q
- Lint:    uv run ruff check . && uv run ruff format --check .
- Run:     FILL_IN after the first slice lands

## Architecture
- FILL_IN after the first slices land (entry point, module boundaries, where logic vs IO lives). Keep to 5 lines.

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
