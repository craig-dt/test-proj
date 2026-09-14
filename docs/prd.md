# Product Requirements Document

|  |  |
| :-: | :-: |
| **Document Title** | flowtest v0.1 |
| **Author** | Craig |
| **Last Updated** | 2026-09-14 |
| **Status** | Draft |
| **Stakeholders** | Craig (PM, approver) · eng-reviewer agent (feasibility review) |
| **Target Release** | v0.1 (GitHub milestone `v0.1`); date TBD |

-----

## Revision History

|  |  |  |  |
| :-: | :-: | :-: | :-: |
| **Date** | **Author** | **Version** | **Change Summary** |
| 2026-09-14 | Craig | 0.1 | Initial draft |

-----

## 1. Problem Statement

A SOC analyst or threat hunter often holds a NetFlow-style CSV export from a firewall or flow collector and ten minutes to answer three questions: who is talking the most, which ports are in play, and is any internal host calling out on a suspiciously regular schedule (beaconing, the classic sign of malware checking in with a command-and-control server). Today those answers need a SIEM or a Zeek plus RITA stack; research (`docs/research.md`) found that RITA, the only actively maintained tool with a published multi-signal beacon score, requires Zeek logs and a ClickHouse database, and that the lightweight alternatives either load the whole file into pandas or reduce beaconing to a single statistic that confuses "regular" with "busy".

A day of enterprise flow is tens of millions of rows. Spreadsheets fail on it, ad-hoc `awk` gives counts but not regularity, and beaconing goes unnoticed until something else fires. The cost of inaction is a slow first look and missed C2 check-ins in exactly the data the analyst already has.

-----

## 2. Goals

- **Goal 1 — Three answers from one CSV:** `top-talkers`, `top-ports` and `beacons` run over the 7-column CSV with no server, database or network access.
- **Goal 2 — Laptop scale:** on a 1 GB CSV (about 10 million rows) on a 16 GB laptop, `top-talkers` and `top-ports` finish within 60 s, `beacons` within 180 s, and peak resident memory stays under 1 GB for every command.
- **Goal 3 — Beacon ranking that matches the textbook case:** a planted tuple connecting every 60 s ± 2 s for 30 flows ranks first; a browser-like host with hundreds of irregular flows to many destinations is absent from the top 5.
- **Goal 4 — Robust to dirty exports:** malformed rows never abort a run; they are counted and reported on stderr, and the exit code stays 0.
- **Goal 5 — Scriptable:** `--json` emits exactly one JSON object on stdout that `jq .` parses, with a `results` array and a `meta` object.

-----

## 3. Non-Goals

- Not a replacement for Zeek, Suricata or a SIEM. flowtest is a triage tool.
- Does not declare anything a beacon. It ranks tuples by score; the analyst decides.
- No enrichment of any kind: no GeoIP, WHOIS, threat intelligence or DNS.
- No persistent state, configuration files, safelists or plugins.
- No GUI, web output or charts.
- No sorting of unsorted input; the tool detects disorder and stops.
- Windows support is not promised in v0.1.

-----

## 4. Out of Scope

|  |  |  |
| :-: | :-: | :-: |
| **Item** | **Reason** | **Future Phase?** |
| PCAP, IPFIX binary, sFlow input | CSV is the only format the target user has on their laptop | TBD |
| GeoIP / WHOIS / threat-intel / DNS enrichment | Offline means offline; enrichment needs network or large data files | No |
| Safelist file for known-benign destinations | Conflicts with the no-config-files rule; prevalence covers the common cases | Yes |
| `--exclude-port` / `--exclude-dst` flags | Hides NTP-tunnelled C2 from the analyst; not needed for the toy | TBD |
| `--window` flag on `beacons` | Whole-file analysis chosen for v0.1 (Q5 of the grill) | TBD |
| `--min-score` filter on `beacons` | Ranked list with `--limit` is the v0.1 contract; a threshold needs calibration we do not have | Yes (P2) |
| Disk-backed sort of unsorted input | Doubles beacon runtime and adds an external sort to a toy | TBD |
| Windows | Nice-to-have only; macOS and Linux are the targets | TBD |
| Colour themes / configurable output | Two rendering paths (TTY colour, plain) are enough | No |
| Machine-learning or FFT-based periodicity | Statistical scoring only, per research brief | No |

-----

## 5. Background & Context

Research (`docs/research.md`, 2026-09-14) surveyed how existing tools score beaconing. Findings that shape this PRD:

- **RITA v5** (Active Countermeasures, GPL-3.0, v5.1.2 May 2026) is the de facto scorer. Its score is a weighted average of four sub-scores in [0, 1]: interval regularity, byte-size consistency, hourly-histogram shape and time-span coverage, each weighted 0.25 by default, followed by a prevalence adjustment of ±15 %. Formulas were read from its source.
- **No Zeek package** scores beaconing statistically; the Zeek ecosystem feeds RITA.
- **Lightweight scorers** (zeek-quick, GTK Cyber, Flare, QFunction) use a single statistic such as coefficient of variation with a 20 to 30 flow minimum. They are simpler and weaker.
- **Streaming feasibility:** three of RITA's four sub-scores stream trivially; interval and size statistics can use capped integer histograms. Memory scales with the number of frequent tuples, not rows, which requires a counting pre-pass.
- **False positives** (NTP, update checkers, monitoring heartbeats) are handled by existing tools with safelists and prevalence. Only prevalence is compatible with the no-config rule.

The research brief (`docs/research-brief.md`) and the glossary (`CONTEXT.md`) define the terms used below: Flow, Tuple, Pair, Internal host, Outbound flow, Interval, Beacon score, Prevalence.

-----

## 6. Feature Description

### 6.1 CSV ingestion

**Description:** Every command reads the same input contract from a path argument or stdin (`-`), one row at a time, never holding the file in memory.

**Key Business Rules / Logic:**

- The header row is mandatory and must be exactly `ts,src_ip,dst_ip,dst_port,proto,bytes,packets` in that order. Any other header is "input could not be read": exit code 2.
- `ts` is ISO-8601 (`2026-09-14T18:04:11Z`) or Unix epoch seconds. Both may appear in the same file. ISO-8601 without a zone is UTC. Epoch may carry a fractional part. Sub-second precision is truncated to whole seconds.
- `proto` is `tcp`, `udp` or `icmp`, case-insensitive. For `icmp`, `dst_port` may be empty or `0`.
- `bytes` and `packets` are non-negative integers.
- `src_ip` and `dst_ip` are IPv4 or IPv6 addresses (IPv6 handling is Open Question 3).
- A row that violates any rule above is a Skipped row: counted, never fatal. At the end of the run stderr reports `N rows skipped`. Skipped rows do not change the exit code.
- A file that cannot be opened, is empty, or has a bad header exits with code 2. A usage error (bad flag, missing argument, non-positive `--limit`) exits with code 1. Success exits 0.
- The input may be tens of millions of rows; no command loads the whole file.

### 6.2 `top-talkers`

**Description:** `flowtest top-talkers <file> [--by bytes|packets|flows] [--limit N] [--direction src|dst|pair]` ranks hosts or pairs by traffic volume over the whole file.

**Key Business Rules / Logic:**

- `--by` selects the ranking measure: total bytes (default), total packets or flow count. The other two measures are shown alongside.
- `--direction src` (default) ranks source hosts; `dst` ranks destination hosts; `pair` ranks (source, destination) Pairs.
- `--limit` defaults to 20 and must be a positive integer.
- Ties break by key ascending (IP address order, then destination for pairs) so output is deterministic.
- All flows count, including icmp and internal-to-internal.

### 6.3 `top-ports`

**Description:** `flowtest top-ports <file> [--limit N] [--proto tcp|udp]` ranks destination ports by flow count, showing total bytes alongside.

**Key Business Rules / Logic:**

- Ranking is by flow count; ties break by port number ascending.
- `--proto` restricts to tcp or udp; default is both, reported as separate rows (`443/tcp`, `53/udp`).
- icmp flows are ignored by this command and stderr reports how many were ignored.
- Well-known ports show a service name in Table output from a built-in table (for example `443 https`); no external lookup. Unknown ports show a blank name. JSON output carries the name as a nullable field.
- `--limit` defaults to 20 and must be a positive integer.

### 6.4 `beacons`

**Description:** `flowtest beacons <file> [--min-flows N] [--internal CIDR ...] [--limit N]` finds Tuples whose Outbound flows recur at regular intervals and ranks them by Beacon score, highest first. This is the command that matters; the other two exist so results have context.

**Key Business Rules / Logic:**

- **Candidates.** Only Outbound flows are considered: source is an Internal host, destination is an External host. Internal hosts are, by default, RFC 1918 ranges plus loopback and link-local. `--internal <CIDR>` (repeatable) replaces the default list for the run.
- **Grouping.** Scoring is per Tuple: (source, destination, destination port).
- **Gate.** A Tuple is scored only if it has at least `--min-flows` flows (default 10) and at least 3 non-zero Intervals. Zero-second Intervals (several flows in the same second) are ignored by the interval statistics but counted as flows.
- **Input order.** Rows must be in non-decreasing `ts` order. On the first out-of-order row the command stops with exit code 2 and a message naming the row number. Only `beacons` checks order.
- **Analysis span.** The whole file. The hourly histogram uses 24 bins spread evenly across the file's time span (one bin per hour when the span is 24 h; wider bins for longer spans, narrower for shorter).
- **Beacon score** follows RITA v5 (see ADR 0001 and `docs/research.md`). Four sub-scores, each in [0, 1], averaged with equal weights of 0.25:
  1. **Interval regularity:** mean of (1 − |Bowley skewness| of the Intervals) and ((median − MAD) / median of the Intervals), where MAD is the median absolute deviation; each term clamped to [0, 1].
  2. **Byte-size consistency:** the same two statistics computed on the per-flow byte counts.
  3. **Histogram shape:** 1 − (standard deviation / mean) of the 24 bin counts, 0 when that ratio exceeds 1.
  4. **Duration coverage:** the larger of (Tuple time span / file time span) and (longest run of consecutive non-empty bins / 12), only when the Tuple appears in at least 6 bins; otherwise 0.
- **Prevalence adjustment.** Prevalence is the share of Internal hosts in the file with at least one flow to the Tuple's destination. Score +0.15 when Prevalence ≤ 2 %, −0.15 when Prevalence ≥ 50 %, then clamped to [0, 1].
- **Output.** All qualifying Tuples ranked by score descending, cut by `--limit` (default 20). Ties break by Tuple key ascending. Each row shows: source, destination, port/proto, flows, median Interval in seconds, the four sub-scores, the count of Internal hosts talking to that destination, and the final score to three decimals.
- No Tuple is ever labelled a beacon; the score is the whole verdict.

### 6.5 Output rendering

**Description:** Every command renders either a human-readable table or a single JSON object.

**Key Business Rules / Logic:**

- **Table output** (default): header row, column-aligned, numbers right-aligned, byte totals in human units (`1.2 GB`). Colour (bold header, highlighted first row) only when stdout is a TTY; plain text when piped or redirected. `--no-color` forces plain text; the `NO_COLOR` environment variable is honoured.
- **JSON output** (`--json`): exactly one JSON object on stdout, nothing else. Shape: `{"results": [...], "meta": {...}}`. `meta` contains `command`, `input` (path or `-`), `rows` (rows read), `rows_skipped`, `elapsed_s`, `version`. Numbers are raw integers or floats, never formatted strings. Skipped-row and informational messages still go to stderr.
- `--version` prints the tool version from the package metadata; `--help` documents every command and flag.

### 6.6 Packaging and platform

**Description:** flowtest is a Python 3.12 command-line tool installable with `uv tool install .` or runnable with `uv run flowtest`.

**Key Business Rules / Logic:**

- Standard library preferred. A third-party dependency is acceptable only if it removes a lot of code; argument parsing and table formatting are hand-rolled or stdlib.
- Runs on macOS and Linux. Windows is nice-to-have.
- No network access at runtime, ever.

-----

## 7. User Stories

|  |  |  |  |
| :-: | :-: | :-: | :-: |
| **ID** | **Priority** | **User Story** | **Notes** |
| US-01 | P0 | As a SOC analyst, I want to rank hosts by bytes, packets or flow count so that I see who is talking the most in one command. | `top-talkers`, src and dst directions |
| US-02 | P0 | As a SOC analyst, I want to rank destination ports with service names so that I know what protocols are in play. | `top-ports` |
| US-03 | P0 | As a threat hunter, I want internal hosts calling out on a regular schedule ranked by a published score so that I can triage likely C2 first. | `beacons`, RITA v5 formula |
| US-04 | P0 | As a SOC analyst, I want malformed rows counted and reported rather than fatal so that one bad line does not cost me the run. | stderr count, exit 0 |
| US-05 | P0 | As a detection engineer, I want `--json` to emit one clean object so that I can pipe flowtest into `jq` and scripts. | `results` + `meta` |
| US-06 | P0 | As a SOC analyst, I want a 1 GB export to finish in minutes without swapping so that the tool is usable on my laptop. | 60 s / 180 s / <1 GB RSS |
| US-07 | P1 | As a SOC analyst, I want to rank (source, destination) pairs so that I can see whether a suspicious tuple is also a heavy talker. | `--direction pair` |
| US-08 | P1 | As a threat hunter at a site with public internal ranges, I want to tell flowtest which CIDRs are internal so that outbound detection is correct. | `--internal`, repeatable |
| US-09 | P1 | As a detection engineer, I want to read from stdin so that flowtest fits in a pipeline. | `-` argument |
| US-10 | P1 | As a threat hunter, I want an out-of-order file to fail loudly so that I never trust beacon scores computed on shuffled data. | exit 2 with row number |
| US-11 | P1 | As a SOC analyst, I want colour in the terminal and plain text in a pipe so that both reading and redirecting work. | `--no-color`, `NO_COLOR` |
| US-12 | P1 | As a threat hunter, I want shared destinations down-weighted so that update servers and NTP do not top the list. | Prevalence ±15 % |
| US-13 | P2 | As a detection engineer, I want `--min-score` on `beacons` so that a script only receives strong candidates. | Future phase |

-----

## 8. UX Requirements

**Key Workflows:**

- **Ten-minute triage:** analyst runs `top-talkers`, then `top-ports`, then `beacons` on the same file; reads three tables; cross-checks a suspicious tuple against the talker and port tables.
- **Scripted triage:** engineer runs `flowtest beacons export.csv --json | jq '.results[] | select(.score > 0.8)'` in a cron job; stderr goes to a log.
- **Dirty file:** analyst runs any command on an export with a few bad lines; sees `3 rows skipped` on stderr and a complete table on stdout.
- **Wrong file:** analyst points at a file with a different header; gets a one-line explanation and exit code 2, not a traceback.

**Design Constraints / Guidelines:**

- Table columns fixed-width and aligned; readable at 120 columns; long IPv6 addresses may widen a column but never wrap.
- Numbers in Table output use human units for bytes and plain integers elsewhere; JSON never formats numbers.
- One line on stderr per informational message; no progress bars in v0.1.
- Help text fits one screen per command.

**Accessibility Requirements:**

- Colour never carries meaning on its own; rank order and values do. `--no-color` and `NO_COLOR` disable it.
- No Unicode box-drawing; ASCII only in tables so screen readers and plain terminals behave.

**Prototype / Mockup Links:**

- None. Text-only tool.

-----

## 9. Acceptance Criteria

### US-01: Top talkers

- Given the 12-row fixture with three source hosts, when `top-talkers --limit 2` runs, then exactly the two heaviest sources by bytes print, heaviest first.
- Given the same fixture, when `--by flows` runs, then ranking is by flow count and bytes and packets still appear as columns.
- Given two hosts with identical totals, when ranked, then the lower IP address prints first.
- Given `--limit 0` or `--limit -1`, when any command runs, then exit code is 1 and stdout is empty.

### US-02: Top ports

- Given a fixture with tcp 443, udp 53 and icmp flows, when `top-ports` runs, then `443/tcp` shows `https`, `53/udp` shows `dns`, icmp rows are absent, and stderr says how many icmp flows were ignored.
- Given `--proto udp`, when it runs, then only udp ports appear.

### US-03: Beacons

- Given a fixture where `10.0.0.5 → 203.0.113.9:443` connects every 60 s ± 2 s for 30 flows, when `beacons` runs, then that tuple ranks first and its median interval is 60.
- Given that fixture plus a browser-like host with hundreds of irregular flows to many destinations, when `beacons` runs, then no tuple from the browser-like host is in the top 5.
- Given a tuple with 9 flows and `--min-flows 10`, when `beacons` runs, then the tuple is absent from results.
- Given a tuple of 12 flows all within the same second, when `beacons` runs, then it is absent (fewer than 3 non-zero intervals).
- Given a perfectly regular tuple (all intervals equal, all sizes equal, present in every hour of a 24 h file), when scored, then its pre-prevalence score is 1.000.
- Given an external host that 60 % of internal hosts talk to, when a tuple to it is scored, then its score is 0.15 lower than the unadjusted score, floored at 0.

### US-04: Skipped rows

- Given a file with 3 malformed rows, when each of the three commands runs, then it completes, stderr contains `3 rows skipped`, and the exit code is 0.
- Given a row with `proto=ICMP` and empty `dst_port`, when parsed, then it is not skipped.

### US-05: JSON output

- Given any command with `--json`, when it runs, then stdout parses with `jq .`, contains a `results` array and a `meta` object, and contains nothing else.
- Given the 3-malformed-row file, when `--json` runs, then `meta.rows_skipped == 3` and `meta.rows` equals the total data rows read.
- Given `--json`, when a row is skipped, then the skipped-row message appears on stderr, not stdout.

### US-06: Large file

- Given the generated 10 M-row (~1 GB) synthetic file on a 16 GB laptop, when `top-talkers` and `top-ports` run, then each completes within 60 s with peak RSS under 1 GB.
- Given the same file, when `beacons` runs, then it completes within 180 s with peak RSS under 1 GB and the planted beacons rank in the top 5.

### US-07: Pair direction

- Given the 12-row fixture, when `top-talkers --direction pair --limit 3` runs, then three (source, destination) rows print ranked by bytes.

### US-08: Internal override

- Given a fixture whose "internal" hosts are in `203.0.113.0/24`, when `beacons --internal 203.0.113.0/24` runs, then tuples sourced there are scored and RFC 1918 sources are treated as external.

### US-09: Stdin

- Given `cat fixture.csv | flowtest top-ports -`, when it runs, then output equals running on the path.

### US-10: Out-of-order input

- Given a file whose row 41 has an earlier `ts` than row 40, when `beacons` runs, then it exits 2 and stderr names row 41; when `top-talkers` runs on the same file, then it succeeds.

### US-11: Colour

- Given stdout is not a TTY, when any table prints, then the bytes contain no escape sequences.
- Given `NO_COLOR=1` or `--no-color` on a TTY, when a table prints, then no escape sequences appear.

### US-12: Prevalence

- Given a destination reached by exactly one of 100 internal hosts, when its tuple is scored, then the score is 0.15 higher than unadjusted, capped at 1.

-----

## 10. Technical Considerations

**Architecture / System Design Notes:**

- Single-pass streaming aggregation for `top-talkers` and `top-ports`; state is one counter per key.
- `beacons` is two passes over the input: a counting pass that keeps only a flow count per Tuple and the per-destination internal-host set, then a scoring pass that keeps full state only for Tuples meeting the gate. Stdin therefore cannot be used with `beacons` unless buffered to a temp file; this is Open Question 4.
- Interval and byte-size statistics come from per-Tuple integer histograms (value → count) capped in cardinality, so memory is bounded by the number of qualifying Tuples, not rows.
- The scoring formula is defined in Section 6.4 and ADR 0001; how it is computed is for `docs/spec.md`.

**Dependencies (internal and external):**

- Python 3.12 standard library: `csv`, `ipaddress`, `statistics`, `argparse`, `json`, `datetime`.
- No runtime network. No third-party packages unless justified in the PR.
- Built-in port-to-service table maintained in the repo.

**Data & Privacy Considerations:**

- Flow exports contain IP addresses, which are personal data in some jurisdictions. flowtest reads locally, writes only to stdout and stderr, and creates no files, caches or logs.
- No telemetry.

**Performance / Scale Requirements:**

- Reference input: synthetic 10 M rows, about 1 GB, generated by a bundled seeded script.
- Targets: `top-talkers`, `top-ports` ≤ 60 s; `beacons` ≤ 180 s; peak RSS < 1 GB on a 16 GB laptop; no swapping.
- Performance check is a documented manual step before release, recorded in the PR; CI runs the small fixtures only.

-----

## 11. Success Metrics

|  |  |  |  |
| :-: | :-: | :-: | :-: |
| **Metric** | **Target** | **How Measured** | **Review Date** |
| Wall time, 1 GB synthetic file, `top-talkers` and `top-ports` | ≤ 60 s each | `time` on the reference laptop, recorded in the release PR | v0.1 release |
| Wall time, 1 GB synthetic file, `beacons` | ≤ 180 s | Same | v0.1 release |
| Peak RSS, any command, 1 GB file | < 1 GB | `/usr/bin/time -l` (macOS) or `-v` (Linux) | v0.1 release |
| Planted beacon rank on synthetic file | Every planted beacon in top 5 | Automated fixture test | Every CI run |
| Browser-noise false positive | 0 browser-like tuples in top 5 | Automated fixture test | Every CI run |
| Dirty-file completion | 100 % of commands exit 0 with correct skipped count | Automated fixture test | Every CI run |
| JSON validity | `jq .` exit 0 on every `--json` run | Automated fixture test | Every CI run |

-----

## 12. Risks & Mitigations

|  |  |  |  |
| :-: | :-: | :-: | :-: |
| **Risk** | **Likelihood** | **Impact** | **Mitigation** |
| Tuple cardinality makes the counting pass exceed 1 GB RSS | Med | High | Compact keys; measure on the synthetic file in the first slice; raise as an eng-review item |
| Flow exports split or merge connections, distorting intervals | Med | Med | Document "one flow ≈ one connection"; ignore zero-second intervals; state in help text |
| Histogram capping alters scores for noisy tuples | Low | Low | Deterministic capping rule; property test that a true beacon scores the same capped or uncapped |
| Formula fidelity to RITA is unverified beyond source reading | Med | Low | Call it "RITA-inspired" in docs; cross-check one tuple against RITA if fidelity matters later |
| Prevalence misfires on small files (few internal hosts) | Med | Med | Show the host count in output; consider a minimum-host floor as an eng-review question |
| Stdlib CSV parsing too slow for the 60 s target on older laptops | Med | Med | 2× headroom in the target; profile early; a single justified dependency is allowed by the constraints |
| Stdin cannot be re-read for the two-pass `beacons` | High | Low | Spool stdin to a temp file for `beacons` only, or document the limitation (Open Question 4) |

-----

## 13. Open Questions

|  |  |  |  |  |
| :-: | :-: | :-: | :-: | :-: |
| **#** | **Question** | **Owner** | **Target Date** | **Resolution** |
| 1 | Target release date for v0.1? | Craig | Before slice stage | TBD |
| 2 | Should `--exclude-port` / `--exclude-dst` ship in v0.1 or stay out? | Craig | Eng review | TBD (PRD assumes out) |
| 3 | IPv6: accept and treat `fc00::/7`, `::1`, `fe80::/10` as internal by default, or IPv4 only in v0.1? | Craig | Eng review | TBD (PRD recommends accept) |
| 4 | `beacons` from stdin: spool to a temp file, or reject `-` for that command? | eng-reviewer | Eng review | TBD (PRD recommends spool) |
| 5 | Prevalence on small files: apply a minimum internal-host count before adjusting? | eng-reviewer | Eng review | TBD |
| 6 | Windows: test in CI or state unsupported? | Craig | Before release | TBD |

15. Basic Test Cases

|  |  |  |  |  |
| :-: | :-: | :-: | :-: | :-: |
| **#** | **Case** | **Expected Behavior** | **Observed Behavior** | **Pass/Fail** |
| 1 | 12-row fixture, `top-talkers --limit 2` | Two heaviest sources by bytes, heaviest first |   |   |
| 2 | Fixture with tcp/udp/icmp, `top-ports` | 443/tcp https, 53/udp dns; icmp absent; stderr count |   |   |
| 3 | Planted 60 s ± 2 s beacon, 30 flows, `beacons` | Tuple ranks first; median interval 60 |   |   |
| 4 | Planted beacon plus browser-noise host, `beacons` | No browser-host tuple in top 5 |   |   |
| 5 | 3 malformed rows, each command | Completes; stderr `3 rows skipped`; exit 0 |   |   |
| 6 | 3 malformed rows, `--json` | `jq .` parses; `meta.rows_skipped == 3`; nothing else on stdout |   |   |
| 7 | Bad header | Exit 2; one-line message; no traceback |   |   |
| 8 | `--limit 0` | Exit 1 |   |   |
| 9 | Row 41 earlier than row 40, `beacons` | Exit 2; message names row 41 |   |   |
| 10 | Same file, `top-talkers` | Succeeds |   |   |
| 11 | Perfectly regular 24 h tuple | Pre-prevalence score 1.000 |   |   |
| 12 | Destination reached by 60 % of internal hosts | Score −0.15, floored at 0 |   |   |
| 13 | Destination reached by 1 of 100 internal hosts | Score +0.15, capped at 1 |   |   |
| 14 | `--internal 203.0.113.0/24` | Sources in that range scored; RFC 1918 sources external |   |   |
| 15 | Piped stdout | No escape sequences |   |   |
| 16 | 1 GB synthetic file, all commands (manual) | ≤ 60 s / ≤ 60 s / ≤ 180 s; RSS < 1 GB; planted beacons in top 5 |   |   |

-----

## 14. References & Related Documents

- Research brief: `docs/research-brief.md`
- Research findings and sources: `docs/research.md`
- Glossary: `CONTEXT.md`
- ADR 0001, beacon scoring formula: `docs/adr/0001-rita-v5-beacon-score.md`
- RITA source, `analysis/beacons.go` and `default_config.hjson`: https://github.com/activecm/rita
- GitHub issue: craig-dt/test-proj #4 (PRD), #2 (research)
