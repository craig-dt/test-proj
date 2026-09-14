#!/usr/bin/env bash
# PostToolUse hook (Edit|Write|MultiEdit): format the touched file. Never blocks.
set -u
f="$(cat | jq -r '.tool_input.file_path // empty' 2>/dev/null)"
[ -z "$f" ] || [ ! -f "$f" ] && exit 0
case "$f" in
  *.py)  command -v ruff >/dev/null && ruff format -q "$f" && ruff check -q --fix "$f" ;;
  *.ts|*.tsx|*.js|*.jsx|*.json|*.md)
         command -v prettier >/dev/null && prettier --log-level silent --write "$f" ;;
  *.sh)  command -v shfmt >/dev/null && shfmt -w "$f" ;;
esac
exit 0
