#!/usr/bin/env python3
"""Derive docs/status.yaml from GitHub (the source of truth) and print a compact summary.

Stage detection is by artifact + issue state, so nothing has to be hand-maintained:
  research   → docs/research.md merged on main
  prd        → docs/prd.md
  eng_review → docs/eng-review.md
  slice      → ≥1 issue in the milestone
  build      → open slice issues remain
  verify     → all slice issues closed, final-pass not recorded
  done       → status.yaml has `verified: <date>` (set by /project:verify final pass via --mark-verified)

Usage: scripts/status.py [--milestone NAME] [--json] [--mark-verified]
Only stdlib + gh CLI. Preserves notion_url / prd_gdoc_url from the existing yaml.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
STATUS = ROOT / "docs" / "status.yaml"
STAGES = ["research", "prd", "eng_review", "slice", "build", "verify"]
ARTIFACTS = {"research": "docs/research.md", "prd": "docs/prd.md", "eng_review": "docs/eng-review.md"}
RUNNER_LABELS = {"agent:in-progress", "agent:pr-open", "agent:failed"}


def gh(*args: str) -> str:
    return subprocess.check_output(["gh", *args], text=True)


def gh_json(*args: str):
    return json.loads(gh(*args))


def read_kv(path: pathlib.Path) -> dict:
    """Tiny flat-YAML reader for the keys we preserve (avoids a PyYAML dependency)."""
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for line in path.read_text().splitlines():
        m = re.match(r'^(\w+):\s*"?([^"#]*)"?\s*(#.*)?$', line)
        if m:
            out[m.group(1)] = m.group(2).strip()
    return out


def on_main(rel: str) -> bool:
    try:
        subprocess.check_output(["git", "cat-file", "-e", f"origin/main:{rel}"], stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return (ROOT / rel).exists()  # fall back to working tree (pre-push)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--milestone")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--mark-verified", action="store_true")
    a = ap.parse_args()

    prev = read_kv(STATUS)
    project = prev.get("project") or ROOT.name
    milestone = a.milestone or prev.get("milestone") or project
    repo = gh("repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner").strip()
    subprocess.run(["git", "fetch", "-q", "origin", "main"], check=False)

    ms_args = ["--milestone", milestone]
    try:
        issues = gh_json(
            "issue",
            "list",
            *ms_args,
            "--state",
            "all",
            "--limit",
            "500",
            "--json",
            "number,title,state,labels,url",
        )
    except subprocess.CalledProcessError:
        issues = []
    for i in issues:
        i["labels"] = {l["name"] for l in i["labels"]}
    slices = [i for i in issues if not (i["labels"] & {"needs-triage", "wontfix"})]
    open_ = [i for i in slices if i["state"] == "OPEN"]
    closed = [i for i in slices if i["state"] == "CLOSED"]
    prs = gh_json("pr", "list", "--state", "open", "--json", "number,title,headRefName,url,statusCheckRollup")

    done = {s: on_main(p) for s, p in ARTIFACTS.items()}
    done["slice"] = bool(slices)
    done["build"] = bool(slices) and not open_
    verified = prev.get("verified") or (
        dt.datetime.now().astimezone().date().isoformat() if a.mark_verified else ""
    )
    done["verify"] = bool(verified)
    current = next((s for s in STAGES if not done[s]), "done")

    def bucket(label):
        return [i for i in open_ if label in i["labels"]]

    summary = {
        "project": project,
        "repo": repo,
        "milestone": milestone,
        "current_stage": current,
        "stages": {s: ("completed" if done[s] else "pending") for s in STAGES},
        "slices": {"total": len(slices), "closed": len(closed), "open": len(open_)},
        "ready": [i["number"] for i in bucket("ready-for-agent")],
        "in_progress": [i["number"] for i in bucket("agent:in-progress")],
        "pr_open": [i["number"] for i in bucket("agent:pr-open")],
        "failed": [i["number"] for i in bucket("agent:failed")],
        "needs_info": [i["number"] for i in bucket("needs-info")],
        "human": [i["number"] for i in bucket("ready-for-human")],
        "blocked": [i["number"] for i in bucket("blocked")],
        "open_prs": [
            {
                "number": p["number"],
                "branch": p["headRefName"],
                "url": p["url"],
                "ci": _ci_state(p.get("statusCheckRollup") or []),
            }
            for p in prs
        ],
        "notion_url": prev.get("notion_url", ""),
        "prd_gdoc_url": prev.get("prd_gdoc_url", ""),
        "verified": verified,
        "updated": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
    }
    summary["next"] = _next_command(summary)

    STATUS.parent.mkdir(parents=True, exist_ok=True)
    STATUS.write_text(_to_yaml(summary))

    if a.json:
        print(json.dumps(summary, indent=2))
    else:
        s = summary
        print(f"{s['project']} [{s['milestone']}] — stage: {s['current_stage']}")
        print(
            f"  slices: {s['slices']['closed']}/{s['slices']['total']} closed · ready {s['ready']} · "
            f"in-progress {s['in_progress']} · pr-open {s['pr_open']}"
        )
        if s["failed"] or s["needs_info"] or s["human"]:
            print(f"  attention: failed {s['failed']} · needs-info {s['needs_info']} · human {s['human']}")
        for p in s["open_prs"]:
            print(f"  PR #{p['number']} {p['branch']} ci={p['ci']} {p['url']}")
        print(f"  next: {s['next']}")
    return 0


def _ci_state(rollup) -> str:
    states = {c.get("conclusion") or c.get("state") or "PENDING" for c in rollup}
    if not states:
        return "none"
    if states & {"FAILURE", "ERROR", "CANCELLED", "TIMED_OUT"}:
        return "failing"
    if states <= {"SUCCESS", "NEUTRAL", "SKIPPED"}:
        return "green"
    return "pending"


def _next_command(s) -> str:
    st = s["current_stage"]
    if st == "research":
        return "/project:research <description>"
    if st == "prd":
        return "/project:prd <raw requirements>"
    if st == "eng_review":
        return "/project:eng-review"
    if st == "slice":
        return "/project:slice"
    if st == "build":
        if s["pr_open"] or s["open_prs"]:
            return (
                f"/project:verify {s['open_prs'][0]['number']}" if s["open_prs"] else "/project:verify <pr>"
            )
        if s["failed"]:
            return f"inspect #{s['failed'][0]} (agent:failed), then scripts/agent-run.sh --issue {s['failed'][0]}"
        if s["needs_info"]:
            return f"answer #{s['needs_info'][0]} on GitHub, relabel ready-for-agent"
        if s["ready"]:
            return f"scripts/agent-run.sh --milestone '{s['milestone']}'"
        if s["human"]:
            return f"/project:build {s['human'][0]} (ready-for-human — supervised)"
        return "all slices claimed; wait for PRs"
    if st == "verify":
        return "/project:verify   (final pass)"
    return "/project:status publish"


def _to_yaml(s) -> str:
    def q(v):
        return json.dumps(v)

    lines = [
        "# Derived by scripts/status.py from GitHub. Do not edit by hand; re-run the script.",
        f"project: {q(s['project'])}",
        f"repo: {q(s['repo'])}",
        f"milestone: {q(s['milestone'])}",
        f"current_stage: {s['current_stage']}",
        f"notion_url: {q(s['notion_url'])}",
        f"prd_gdoc_url: {q(s['prd_gdoc_url'])}",
        f"verified: {q(s['verified'])}",
        f"updated: {q(s['updated'])}",
        "stages:",
    ]
    lines += [f"  {k}: {v}" for k, v in s["stages"].items()]
    lines += [f"slices: {json.dumps(s['slices'])}"]
    for k in ("ready", "in_progress", "pr_open", "failed", "needs_info", "human", "blocked"):
        lines.append(f"{k}: {json.dumps(s[k])}")
    lines.append("open_prs:")
    lines += [f"  - {json.dumps(p)}" for p in s["open_prs"]] or ["  []"]
    lines.append(f"next: {q(s['next'])}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())
