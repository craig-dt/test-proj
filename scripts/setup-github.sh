#!/usr/bin/env bash
# One-time GitHub setup for a pipeline repo: labels, milestone, branch protection on main.
# Usage: scripts/setup-github.sh "<milestone name>" [--with-review]
#   --with-review  also require the `review` check (from .github/workflows/review.yml)
set -euo pipefail
MS="${1:?milestone name required}"; WITH_REVIEW=0; [ "${2:-}" = "--with-review" ] && WITH_REVIEW=1
REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner)"

mk() { gh label create "$1" --color "$2" --description "$3" --force >/dev/null && echo "label $1"; }
mk bug d73a4a "Something is broken"
mk enhancement a2eeef "New feature or improvement"
mk needs-triage ededed "Maintainer must evaluate"
mk needs-info fbca04 "Waiting on reporter / Craig"
mk ready-for-agent 0e8a16 "Fully specified; AFK agent may claim"
mk ready-for-human 5319e7 "Needs a human decision or hands"
mk blocked b60205 "Open blockers; promoted automatically"
mk wontfix ffffff "Will not be actioned"
mk agent:in-progress 1d76db "Runner has claimed this"
mk agent:pr-open 0052cc "Runner opened a PR"
mk agent:failed e11d21 "Runner failed; see comment"
mk skip-review c5def5 "Docs-only PR; review.yml job is skipped"

gh api "repos/$REPO/milestones" -f title="$MS" >/dev/null 2>&1 && echo "milestone $MS" || echo "milestone $MS (exists)"

checks='["ci"]'; [ "$WITH_REVIEW" -eq 1 ] && checks='["ci","review"]'
gh api -X PUT "repos/$REPO/branches/main/protection" --input - >/dev/null <<EOF
{
  "required_status_checks": { "strict": true, "contexts": $checks },
  "enforce_admins": true,
  "required_pull_request_reviews": null,
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_linear_history": true,
  "required_conversation_resolution": true
}
EOF
echo "branch protection on main: PRs only, checks $checks must pass, no force-push/delete, admins included."
echo "NOTE: required_pull_request_reviews is null because a solo repo can't require a second human approver;"
echo "      the fresh-agent review is the '$([ "$WITH_REVIEW" -eq 1 ] && echo review || echo ci)' check. Set it to 1 approval if teammates join."
