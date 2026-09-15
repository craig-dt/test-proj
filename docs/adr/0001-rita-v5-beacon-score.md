---
status: accepted
date: 2026-09-14
---

# Beacon score follows RITA v5's four-sub-score formula

flowtest needs a beacon score an analyst can defend and a PRD can state as acceptance criteria. We adopt the
formula published in RITA v5's source (Active Countermeasures, `analysis/beacons.go`, v5.1.2): four sub-scores
in [0, 1] averaged with equal weights of 0.25 (interval regularity from Bowley skew and median absolute
deviation, byte-size consistency from the same statistics, hourly-histogram shape from coefficient of
variation, and duration coverage), then RITA's prevalence adjustment of ±0.15 at the 2 % and 50 % thresholds.
We chose it because it is the only actively maintained, published, multi-signal formula in the field, analysts
already recognise its numbers, and every part of it can be computed in a streaming pass with bounded memory
(see `docs/research.md`).

## Considered options

- **Coefficient of variation of intervals only** (zeek-quick, GTK Cyber). Simplest, but conflates "regular" with
  "busy" and ignores byte size and time coverage; weakest against jittered or bursty benign traffic.
- **RITA v4's two-part score** with fixed 30-second and 32-byte dispersion constants. Widely documented in blog
  posts, but superseded upstream and its constants do not transfer to flow records.
- **RITA v5** (chosen).

## Consequences

- Scores are "RITA-inspired", not RITA-compatible: RITA groups by host pair and reads Zeek connection logs;
  flowtest groups by (source, destination, port) and reads flow records. Documentation must say so.
- Changing the formula later changes every score analysts have learned; treat as a breaking change.
- Interval and byte-size statistics are computed from a 1000-element reservoir sample per Tuple (PRD
  section 10, issue #29). Scores for Tuples with at most 1000 flows are exact; for Tuples above 1000 flows
  the interval and size sub-scores and the median Interval are sample-based (fair uniform sample, reproducible for a given Python version run to
  run because the sample is seeded from the Tuple key). The histogram and duration sub-scores and the gate
  are always exact.
