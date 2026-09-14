# Issue tracker

Issues live in this repo's **GitHub Issues**, driven with the `gh` CLI.

- Scope: a **milestone** per project (full pipeline) or per feature (`/project:quick`).
- The **agent brief** in an issue body is the contract for whoever builds it. Behavioural, no file paths.
- Create: `gh issue create --title "..." --body-file brief.md --label ready-for-agent --milestone "<name>"`
- Dependencies: a `## Blocked by` section listing `#N`. Blocked issues carry the `blocked` label; the runner
  removes it and adds `ready-for-agent` once every blocker is closed.
- Closing: only via a merged PR that says `Closes #N`. Agents never close issues by hand.
- Runner state labels: `agent:in-progress` (claimed), `agent:pr-open`, `agent:failed` (log posted as comment).
