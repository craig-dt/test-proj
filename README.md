# test-proj

FILL_IN: one-paragraph description of what this project does and for whom.

## Run / test
See `CLAUDE.md` → Commands.

## How work happens here
This repo is built with an agentic pipeline: GitHub issues carry agent briefs; `scripts/agent-run.sh` builds
`ready-for-agent` issues into PRs in isolated worktrees; CI and a fresh-agent review gate every merge.
`docs/status.yaml` is derived (`scripts/status.py`). Domain vocabulary: `CONTEXT.md`; decisions: `docs/adr/`.
