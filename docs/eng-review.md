# Engineering review — flowtest v0.1 PRD

**Date:** 2026-09-14 · **Reviewer:** `eng-reviewer` agent (cold context) · **Issue:** #6 · **Inputs:** `docs/prd.md` (0.1), `docs/research.md`, `docs/research-brief.md`, `CONTEXT.md`, ADR 0001.

Repo state at review: `uv run pytest -q` 1 passed (smoke only), `ruff` clean; no product code exists yet. The reviewer ran three throwaway scripts in its scratchpad (not the repo) to check throughput, memory and the section 6.4 arithmetic; numbers below come from those.

## Summary

The PRD is well structured and mostly consistent with the glossary and ADR, but the beacon acceptance criteria are not guaranteed by the formula they cite: a 60-second beacon that runs for 30 minutes inside a 24-hour file scores about 0.50 under section 6.4, while ordinary irregular browsing spread across the day scores 0.49 to 0.68, so "ranks first" and "no browser tuple in the top 5" can fail depending on fixture details the PRD never states. The two-pass memory design also tracks per-destination host sets in the counting pass, which measurement shows can alone consume 0.5 to 1.1 GB on a browser-heavy 10 M-row file, breaking Goal 2. Both are fixable in the PRD without touching the ADR; the rest are missing guards and contracts that would otherwise be guessed at build time.

## Findings

| ID | Severity | Section | Finding | Cost of ignoring | Recommended change |
|---|---|---|---|---|---|
| F1 | High | Goal 3, 9/US-03, 15/TC3-4 | The planted-beacon fixture (60 s ± 2 s, 30 flows = a 29-minute burst) is scored with bins and coverage rescaled to the *file* span. If the fixture file spans 24 h, hist = 0 and dur = 0 (1 bin < 6-bin gate) so the beacon scores ~0.50; irregular 40-flow browser tuples across the day scored 0.49, 0.55, 0.68 in the check. "Ranks first" is not implied by the formula. | Flagship test is flaky-by-design or passes vacuously; analysts lose trust on day one. | State the fixture: planted tuple spans the whole file (or runs the full 24 h, e.g. 1440 flows at 60 s). Require the browser fixture to contain ≥ 5 tuples that pass the gate so "absent from top 5" is a real assertion. |
| F2 | High | 6.4, 9/US-03 AC5, 15/TC11 | Formula omits guards research.md documents: Bowley skew divides by zero when Q3 = Q1 (exactly the "perfectly regular" fixture); MAD defaults (ts → 1, ds → 0 when median < 1) absent; duration consistency `run/12` reaches 2.0 with 24 consecutive bins (score 1.25) unless clamped; quartile method unspecified. "1.000" holds only with all guards and a flow count that divides evenly into 24 bins (25 hourly flows → 0.952). | Implementer guesses; scores differ at 3 dp between implementations; the 1.000 test either crashes or fails. | Write the guards into 6.4 (force skew 0 when Q3 − Q1 < 10 or median equals a quartile; MAD defaults; clamp every sub-score to [0, 1]; name the quantile method). Define TC11 as 24 flows at 3600 s spanning exactly the file, last timestamp lands in bin 23. |
| F3 | High | 10, 12 row 1 | Counting pass keeps a "per-destination internal-host set". That grows with distinct (internal src, external dst) pairs, not with internal host count as research.md claims. Measured: 1 M destinations × 3 hosts = 546 MB; 200 k × 50 = 1.1 GB. Plus pass-1 tuple counts: 2 M tuples = 585 MB as string tuples, 264 MB packed. | Goal 2 (< 1 GB RSS) fails on realistic files before any scoring happens. | Pass 1: tuple count keyed as packed bytes + set of all internal sources (denominator). Pass 2: host sets only for destinations of qualifying tuples. Update Risk row 1. |
| F4 | High | 6.1, US-09 vs 10, OQ4, Non-Goals, 10 Data & Privacy | 6.1 says every command reads stdin; Section 10 says `beacons` cannot; the recommended fix (spool to temp file) contradicts "creates no files" and "no persistent state", and writes IP data to disk. | Contradiction ships as whichever the builder picks; a silent temp file of personal data is a data-handling regression. | `beacons -` exits 1 with a one-line message; US-09 scoped to `top-talkers`/`top-ports`. Human decision for Craig (OQ4). |
| F5 | High | 6.4 Prevalence, 12 row 5, OQ5 | Denominator undefined (internal hosts seen as src? src or dst? only with Outbound flows?). On the Goal 3 fixture (2 internal hosts) every destination is at 50 % so every tuple gets −0.15, including the planted beacon; TC12/13 need 100-host fixtures. Output shows the numerator but not the total, so the analyst cannot read the share. | Small captures are systematically penalised; tests interact in surprising ways. | Define denominator = distinct Internal hosts that are the source of ≥ 1 Outbound flow. Apply the adjustment only when that count ≥ 10 (Craig to confirm the floor). Add `internal_hosts_total` to `meta`, `prevalence` to each result. |
| F6 | Med | CONTEXT.md Tuple vs 6.4 Output | Tuple key is (src, dst, port) but output shows `port/proto`; 53/tcp and 53/udp to the same host collide into one Tuple. Whether icmp Outbound flows (port empty/0) are candidates is unstated. | Mixed-proto tuples produce nonsense intervals; icmp tunnels either silently excluded or crash on empty port. | Add proto to the Tuple (update glossary, ADR consequence unaffected). State icmp tuples are scored with port 0. |
| F7 | Med | 6.4 Input order, US-10 | Strict *global* non-decreasing `ts` with abort on first violation. Flow collectors commonly emit by flow end or export time; seconds of disorder are normal. Interval maths only needs order *within a Tuple*; span and bins need no order. | Tool refuses many real exports; analyst reaches for `sort` and loses the header, or gives up. | Check order per Tuple (compare to the Tuple's last ts, already stored), same exit-2 behaviour. Decision for Craig; keep Non-Goal "no sorting". |
| F8 | Med | 6.1 `ts` rule | "ISO-8601" subset undefined (space separator, `+02:00`, fractional `Z`). Epoch *milliseconds* (very common) parse as year ~57000 without error, so they are not Skipped rows and they explode the file span and bin width; extreme values raise `OverflowError` in `datetime`. | Silent garbage scores on a common export format; or a traceback. | Accept what `datetime.fromisoformat` accepts plus trailing `Z`; convert offsets to UTC; a `ts` outside [2000-01-01, 2100-01-01) is a Skipped row. Say ms-epoch is rejected. |
| F9 | Med | 6.1, Goal 4 | Dirty-file contract stops at "malformed row". Unhandled: UTF-8 BOM (Excel/firewall exports) fails the exact-header check with exit 2 on a valid file; a non-UTF-8 byte raises `UnicodeDecodeError` mid-file; a field > 128 KB raises `csv.Error`; "row number" (physical line vs logical record) undefined for US-10 and skipped-row messages. | Tracebacks on real exports, violating Goal 4 and the "Wrong file" UX. | Open with `encoding="utf-8-sig", errors="replace", newline=""`; strip whitespace/CR from header cells; any `csv.Error` for a record is a Skipped row; row number = `reader.line_num`. |
| F10 | Med | Goal 2, US-06, 12 row 6 | Measured on Apple Silicon (Py 3.14, in-memory, so optimistic): raw `csv.reader` 5 s / 10 M rows; naive per-row `ipaddress` + `fromisoformat` validation 27 s; memoised by string 11 s. 60 s is reachable only with memoisation; an older Intel laptop with naive validation lands near the limit. Nothing in CI catches regression. | Perf target met by accident or missed late; "reference laptop" undefined. | Record memoised validation as a spec constraint; define the reference laptop; add a 1 M-row scaled CI canary (≤ 10 s) alongside the manual 10 M check. |
| F11 | Med | 10 Performance, US-06 | The seeded synthetic generator is a deliverable with no spec: internal host count, distinct tuples, number of planted beacons, intervals, jitter, spans, byte sizes, noise model. "Planted beacons in top 5" depends entirely on it (see F1). | The generator quietly becomes tuned to pass; RSS numbers are meaningless without a stated tuple cardinality. | Specify: e.g. 500 internal hosts, ~1–2 M distinct outbound tuples, 5 planted beacons with intervals 30 s–15 min running the full 24 h with 5–10 % jitter. |
| F12 | Low | 10, 12 row 3 | Histogram capping and coarsening rule deferred to spec but it changes scores. | Deterministic-but-arbitrary rule to design, test and explain. | Consider a fixed-size reservoir sample (e.g. 1000 intervals/sizes per Tuple): bounded, exact for n ≤ 1000, no coarsening rule. |
| F13 | Low | 6.4 Gate | `--min-flows` default 10 vs research recommendation 20; quartiles on 9 intervals are noisy. | More false positives at the top of the list. | Adopt 20 or state why 10. |
| F14 | Low | 6.1, 8 Wrong file | Error messages that echo untrusted header or row text can inject terminal escape sequences into logs. Output columns themselves are validated fields (good). | Log/terminal spoofing; low likelihood for a local tool. | Print untrusted text via `repr()` or truncate and strip control characters. |
| F15 | Low | 6.5, 9/US-09, 13, 14/15 | Nits: section "15. Basic Test Cases" precedes "14. References"; US-09 "output equals" fails for `--json` (`meta.input`, `elapsed_s`); `--version` reads package metadata but `pyproject.toml` still names the project `test-proj`; RITA's bimodal-fit term is dropped from hist without saying so; "empty file exits 2" vs header-only file undefined. | Small confusions at build time. | Fix numbering; scope US-09 AC to Table output; rename package; note the bimodal deviation in 6.4; header-only → exit 0 with empty results. |

## High findings in detail

**F1 — the flagship test is not implied by the formula.** RITA's hist and dur terms assume the beacon persists across the capture. Section 6.4 rescales 24 bins to the file span, so a 29-minute beacon inside a 24-hour file occupies one bin: hist collapses to 0 (coefficient of variation > 1), the 6-bin gate zeros dur, and the score is 0.25·ts + 0.25·ds ≈ 0.50. Irregular browsing spread across the day earns dur ≈ 0.95 through coverage alone and can exceed that. If instead the fixture file spans only the beacon, the same tuple scores ~0.91 and ranks first easily. The PRD must say which. The maths is fine for the textbook 24-hour case; the fixture is the problem.

**F2 — the formula needs its guards written down.** Section 6.4 reads as complete but the perfectly regular fixture hits three unspecified branches (0/0 in Bowley, MAD default, unclamped run/12). Without a clamp the "sub-score in [0, 1]" statement is violated and the total is 1.25. Also, "24 bins across the span" needs an edge rule: the last flow sits exactly on the final bin edge and must be assigned to bin 23, or the 1.000 fixture gets 0.952.

**F3 — the memory bound is claimed, not shown.** The two-pass design fixes tuple-state memory but the PRD then adds per-destination host sets to pass 1, reintroducing an unbounded structure. Moving those sets to pass 2 for qualifying destinations only restores the bound at zero extra passes.

**F4 — stdin.** Three sections disagree. The cheap, honest answer is to reject `-` for `beacons` in v0.1 and keep US-09 for the single-pass commands.

**F5 — prevalence on small captures.** Every small fixture and most real short captures have few internal hosts; the ±0.15 rule then fires on everything. A floor and a visible total make the adjustment explainable and testable.

## The 60% requirement

**Goal 2 / US-06 (10 M rows, 60 s / 180 s, < 1 GB RSS, stdlib only).** It looks like one line but it dictates: memoised IP/timestamp validation in the shared reader, packed tuple keys, the two-pass design and where prevalence sets live (F3), histogram capping or sampling (F12), the seeded 10 M-row generator (F11), and a manual perf procedure nobody can run in CI. Every other requirement is a counting or formatting problem once this envelope holds.

## Suggested spikes

1. **Formula spike (half a day, before the slice stage):** a ~60-line pure function of 6.4 with guards, run against the three fixtures (perfect 24 h, 60 s × 30 in a 24 h file with browser noise, short file). The reviewer's scratch version already shows F1/F2; the spike's output is the corrected acceptance criteria, not code.
2. **Throughput spike on Python 3.12 from disk via `uv run`:** 1 M rows, raw reader vs memoised validation vs two passes, on the reference laptop. Decide whether validation may be memoised and whether an `ipaddress`-free fast path is needed.
3. **Memory spike with the real generator:** pass-1 RSS at 1 M, 2 M, 5 M distinct outbound tuples with packed keys, and prevalence sets in pass 2 only. This is Risk row 1 made concrete.
4. **Order check on a real export (human, 15 min):** is a real firewall/collector CSV globally sorted by `ts`? Decides F7.

## Simpler alternatives

- Reject stdin for `beacons` instead of spooling (F4).
- Per-Tuple order check instead of global (F7); same code, fewer refusals.
- Reservoir sampling per Tuple instead of capped log-scale histograms (F12).
- Prevalence sets in pass 2 for qualifying destinations only (F3).
- `--min-flows 20` per research: fewer candidate Tuples, less pass-2 state, less noise (F13).

## Verdict: PROCEED WITH CHANGES

The ADR and formula stand; the PRD needs its fixtures, formula guards, prevalence denominator and stdin/memory statements corrected before slicing, otherwise the flagship beacon tests will be written to a specification that does not produce the promised ranking.

## Decisions (filled in during the walkthrough with Craig)

_See the table below; the PRD was updated to revision 0.2 accordingly._

| ID | Decision |
|---|---|
| F1 | Accepted. Planted beacon spans the whole 24 h file (~1440 flows, score ≥ 0.85); browser fixture must contain ≥ 5 gate-passing tuples; short-burst behaviour documented. |
| F2 | Accepted. RITA's guards written into PRD 6.4; quantile method named; bin-edge rule added; 1.000 fixture = 24 flows at 3600 s spanning the file. |
| F3 | Accepted. Prevalence host sets move to pass 2 for qualifying destinations only; pass 1 holds compact tuple counts and the internal-host denominator. |
| F4 | Accepted (reject). `beacons -` is a usage error, exit 1; stdin scoped to the single-pass commands. OQ4 resolved. |
| F5 | Accepted. Denominator = distinct Internal hosts sourcing ≥ 1 Outbound flow; adjustment only when ≥ 10; `hosts/total` shown per row; `meta.internal_hosts_total`. OQ5 resolved. |
| F6 | Accepted. Protocol added to the Tuple; ICMP Tuples use port 0. Glossary updated. |
| F7 | Craig chose the third option: per-Tuple order check, violating rows dropped and counted (`rows_out_of_order`), run completes with exit 0. Reviewer's caution about heavily shuffled files recorded in PRD 6.4. |
| F8 | Accepted. `fromisoformat` subset plus `Z`; offsets to UTC; timestamps outside [2000, 2100) are Skipped rows; epoch-ms rejected. |
| F9 | Accepted. BOM-tolerant UTF-8 with replacement; header cells stripped; CSV reader errors are Skipped rows; header-only file exits 0; row number = physical line. |
| F10 | Declined. Perf check stays a manual pre-release step (Craig's grill decision); memoised validation and the reference laptop are now specified. |
| F11 | Accepted. Generator shape specified in PRD 10. |
| F12 | Deferred to spec, as the PRD already stated; reviewer's reservoir-sampling suggestion noted there. |
| F13 | Declined. `--min-flows` default stays 10; rationale added to PRD 6.4. |
| F14 | Accepted. Echoed input truncated and stripped of control characters. |
| F15 | Accepted. Section numbering fixed; US-09 AC scoped to Table output; package to be named `flowtest`; bimodal omission stated; header-only file defined. |
