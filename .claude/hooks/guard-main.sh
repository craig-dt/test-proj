#!/usr/bin/env bash
# PreToolUse hook (matcher: Bash). Refuses git write operations while on main/master.
# Exit 2 = block the tool call and feed stderr back to the model.
# Install: ~/.claude/hooks/guard-main.sh (chmod +x), referenced from settings.json.

set -u
input="$(cat)"
cmd="$(printf '%s' "$input" | jq -r '.tool_input.command // empty' 2>/dev/null)"
[ -z "$cmd" ] && exit 0

# Only care about commands that write to the repo history.
if ! printf '%s' "$cmd" | grep -Eq '(^|[;&|[:space:]])git[[:space:]]+(commit|push|merge|cherry-pick|am)\b'; then
  exit 0
fi

# Not in a git repo → nothing to guard.
branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null)" || exit 0

case "$branch" in
  main|master)
    echo "BLOCKED by guard-main.sh: you are on '$branch'. Create a branch first" \
         "(git switch -c agent/issue-N or feat/N-slug), then retry." >&2
    exit 2
    ;;
esac
exit 0
