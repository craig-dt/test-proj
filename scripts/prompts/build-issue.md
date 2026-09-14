You are running unattended inside a git worktree on branch `agent/issue-{{ISSUE}}` of {{REPO}}. Nobody will answer questions.

Run the `/project:build {{ISSUE}}` command exactly as written in the project's commands. Summary of the contract:
- `gh issue view {{ISSUE}} --comments` is the spec (agent brief). Read CLAUDE.md, CONTEXT.md, docs/agents/*, relevant docs/adr/*.
- If the brief is ambiguous and the codebase does not settle it: comment the precise question on the issue, `gh issue edit {{ISSUE}} --add-label needs-info --remove-label ready-for-agent`, and stop. Do not guess.
- Test-first (tdd skill), stay inside the slice, unrelated bugs become new `needs-triage` issues.
- Finish only when lint + full test suite are green (the Stop hook enforces this).
- Commit small with `feat(#{{ISSUE}}): ...`, `git push -u origin HEAD`, then `gh pr create --fill` with a body covering what/why/how-tested and `Closes #{{ISSUE}}`.
- Never merge. Never touch main. Print the PR URL on its own line prefixed `PR: ` as your last output.
