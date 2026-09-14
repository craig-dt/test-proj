# Triage labels

Canonical role → label string (identity mapping; no overrides).

| Role | Label | Meaning |
|---|---|---|
| category | `bug` | something is broken |
| category | `enhancement` | new feature / improvement |
| state | `needs-triage` | maintainer must evaluate |
| state | `needs-info` | waiting on reporter (or on Craig, when an agent hit ambiguity) |
| state | `ready-for-agent` | fully specified; an AFK agent may claim it |
| state | `ready-for-human` | needs a human (judgment call, design, external access) |
| state | `blocked` | has open blockers; promoted automatically |
| state | `wontfix` | will not be actioned (enhancement rejections go to `.out-of-scope/`) |
| runner | `agent:in-progress`, `agent:pr-open`, `agent:failed` | set by `scripts/agent-run.sh` |

Exactly one category and one state label per issue.
