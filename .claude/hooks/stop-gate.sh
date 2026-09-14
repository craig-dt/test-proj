#!/usr/bin/env bash
# Stop / SubagentStop hook: refuse to let the agent declare "done" with red tests or lint errors.
# Only fires when tracked source files changed vs main (so planning/doc sessions are untouched).
# Exit 2 + stderr = "not done yet, here's why" fed back to the model. Exit 0 = allow stop.
#
# Loop safety: Claude Code sets stop_hook_active=true when a Stop hook already blocked once in
# this turn. We allow at most GATE_MAX_BLOCKS blocks per branch (counter in .git) so a stuck
# agent eventually stops and the runner labels the issue agent:failed instead of burning turns.
set -u
GATE_MAX_BLOCKS="${GATE_MAX_BLOCKS:-4}"
TEST_CMD="${GATE_TEST_CMD:-uv run pytest -q -x}"
LINT_CMD="${GATE_LINT_CMD:-uv run ruff check .}"
SRC_GLOB="${GATE_SRC_GLOB:-\.(py|ts|tsx|js|jsx|go|rs)$}"

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || exit 0
base="$(git merge-base HEAD origin/main 2>/dev/null || git merge-base HEAD main 2>/dev/null || echo HEAD~1)"
changed="$( { git diff --name-only "$base"...HEAD; git diff --name-only; git diff --name-only --cached; } 2>/dev/null | sort -u | grep -E "$SRC_GLOB" || true)"
[ -z "$changed" ] && exit 0

branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo detached)"
counter="$(git rev-parse --git-dir)/stop-gate.${branch//\//_}.count"
n=0; [ -f "$counter" ] && n="$(cat "$counter")"
if [ "$n" -ge "$GATE_MAX_BLOCKS" ]; then
  echo "stop-gate: reached $GATE_MAX_BLOCKS blocks on $branch; allowing stop so the runner can mark this failed." >&2
  exit 0
fi

fail=0; out=""
if ! lint_out="$($LINT_CMD 2>&1)"; then fail=1; out+=$'LINT FAILED:\n'"$(printf '%s' "$lint_out" | tail -40)"$'\n'; fi
if ! test_out="$($TEST_CMD 2>&1)"; then fail=1; out+=$'TESTS FAILED:\n'"$(printf '%s' "$test_out" | tail -60)"$'\n'; fi

if [ "$fail" -eq 1 ]; then
  echo $((n+1)) > "$counter"
  {
    echo "stop-gate ($((n+1))/$GATE_MAX_BLOCKS): you changed source files but the suite is not green. Fix before stopping."
    echo "$out"
  } >&2
  exit 2
fi
rm -f "$counter"
exit 0
