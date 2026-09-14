# Research — flowtest beacon scoring

**Date:** 2026-09-14 · **Brief:** `docs/research-brief.md` · **Issue:** #2 · **Time spent:** ~15 min, web + RITA source.

## Summary

Adopt **RITA v5's beacon score**, adapted for one streaming pass: four sub-scores in [0, 1], each weighted
0.25, computed per `(src_ip, dst_ip, dst_port)` triad. Three of the four sub-scores stream trivially. The
fourth (interval and byte-size statistics) needs a per-triad histogram instead of a raw list, which is exact
for integer-second intervals and bounded by capping distinct buckets. Memory is bounded by the number of
triads that pass a minimum-connection filter, not by row count, which forces a cheap counting pre-pass.

## Q1 — How existing tools score beaconing

### RITA v5 (the de facto Zeek-ecosystem beacon scorer)

Source: `analysis/beacons.go` and `default_config.hjson` in [activecm/rita](https://github.com/activecm/rita)
(GPL-3.0, v5.1.2 released 2026-05-07, last push 2026-06-17, 639 stars). Formulas below are read from the code.

**Grouping.** Per source→destination host pair, over connections with at least `unique_connection_threshold`
(default **4**) unique connections. Needs ≥ 4 timestamps and ≥ 3 non-zero intervals or the pair is skipped.

**Final score** = `0.25·ts + 0.25·ds + 0.25·dur + 0.25·hist`, rounded to 3 dp. Weights configurable, must sum to 1.
Display thresholds: base 50, low 70 (out of 100).

| Sub-score | What it measures | Formula (from source) |
|---|---|---|
| **ts** (timestamp) | Regularity of inter-connection intervals | Sort intervals, drop zeros. `ts = (skewScore + madScore) / 2` where `skewScore = 1 − |Bowley|`, `Bowley = (Q3 + Q1 − 2·Q2)/(Q3 − Q1)` (forced to 0 if `Q3 − Q1 < 10` or the median equals a quartile); `madScore = (median − MAD)/median` if `median ≥ 1`, else default 1; clamped to [0, 1]. |
| **ds** (data size) | Consistency of bytes per connection | Same skew + MAD formula on the byte sizes; MAD default score 0 when median < 1. |
| **hist** (histogram) | Shape of the 24 hourly connection counts | `max(cvScore, bimodalFitScore)`. `cvScore = 1 − sd/mean` over the hourly counts, 0 if CV > 1. Bimodal fit rewards 2–3 flat levels (a beacon that alternates cadence), only used when ≥ 11 hours seen. |
| **dur** (duration) | How much of the capture window the pair spans | Only if ≥ 6 distinct hours seen. `max(coverage, consistency)` where `coverage = (lastTs − firstTs)/(datasetMax − datasetMin)` and `consistency = longestConsecutiveHoursRun / 12`. |

RITA v4 (the version most blog posts and the KQL port describe) used a simpler two-part score:
`ts = (1−|skew| + (1 − MADM/30s) + connCountScore)/3`, `ds = (1−|skew| + (1 − MADM/32B) + (1 − modeSize/65535))/3`,
final `(ts + ds)/2`. v5 dropped the fixed 30-second and 32-byte constants in favour of MAD normalised by the median,
and added the histogram and duration terms. Source: [bluraven KQL port of RITA](https://book.bluraven.io/threat-hunting-and-detection/command-and-control/implementing-rita-using-kql).

**Post-score modifiers (v5).** Independent of external lookups: **prevalence** (share of internal hosts that talk
to the destination) adds 15 % if ≤ 2 % of hosts, subtracts 15 % if ≥ 50 %. Also first-seen age (rolling datasets
only), missing HTTP host header, rare TLS signature. Only prevalence is computable from our CSV.

### Zeek ecosystem

There is **no widely used `zkg` package that scores beaconing statistically**. Zeek's package registry has C2-specific
detectors (e.g. [corelight/zeek-caldera-detector](https://github.com/corelight/zeek-caldera-detector) matches Caldera
agent HTTP patterns) and fingerprinting approaches, not generic periodicity scoring. Commercial Corelight beacon
detection is closed. In practice "Zeek beaconing" means feeding `conn.log` to RITA
([Black Hills write-up](https://www.blackhillsinfosec.com/detecting-malware-beacons-with-zeek-and-rita/)).

### Lightweight scorers (single statistic)

| Tool | Statistic | Threshold / minimum | Notes |
|---|---|---|---|
| [zeek-quick](https://github.com/0xPersist/zeek-quick) | Coefficient of variation (CV = sd/mean) of intervals per src/dst | CV < 0.3 **or** ≥ 20 connections flags the pair | Either condition alone flags; reasons reported separately. Single-pass over piped input. |
| [GTK Cyber Python method](https://gtkcyber.com/blog/hunting-c2-beaconing-python/) | CV of intervals per (src, dst, port); byte-size variance as a second signal | CV < 0.1 with ≥ 30 connections = strong; raise to ~0.3 for jittered beacons; need 20–30 check-ins | Suggests FFT for heavy jitter (out of scope). |
| [Flare](https://github.com/austin-taylor/flare) (Austin Taylor, 2017; pandas-based) | Percent of a triad's intervals falling within ±`window` seconds of the modal interval | `min_percent` of connections must sit in the window; `min_interval` filters rapid connections; `MIN_OCCURRENCES` | Groups by (src, dst, port) "triad". Older project; maintenance status not checked. |
| [QFunction Zeek + math](https://qfunction.ai/blog/automated-threat-hunting-for-network-beacons-using-zeek-and-math) | Standard deviation of intervals | Flag pairs at or below the 5th percentile of sd | Percentile threshold needs per-environment tuning. |

**Takeaway.** Every tool agrees on the core signals: interval regularity first, byte-size consistency second, a
minimum connection count as a gate, and time-span coverage as a tiebreaker. RITA is the only one with a published,
multi-signal, weighted score, and it is actively maintained. CV-only scorers are simpler but conflate "regular" with
"busy" (zeek-quick's OR condition is a known noise source).

## Q2 — Which signals stream in one pass with bounded memory

Grouping key: `(src_ip, dst_ip, dst_port)`, matching Flare and the GTK method; RITA groups by host pair only.
Per-triad state below. All assume rows arrive **sorted by `ts`** within a triad (see Risk 1).

| Signal | Streams? | Per-triad state | Notes |
|---|---|---|---|
| Connection count | Yes | 1 int | Gate: skip scoring below `min_conn`. |
| Duration: first/last ts, hours-seen | Yes | 2 ints + 24-bit bitmap | `coverage`, `consistency` exactly as RITA. |
| Histogram: hourly counts | Yes | 24 ints | `cvScore` exact. Bimodal fit exact too. |
| Interval median, MAD, quartiles | **Yes, via histogram** | dict `interval_seconds → count`, plus `last_ts` | Exact for integer-second intervals when distinct-interval count stays bounded. Beacons have few distinct intervals; noisy triads have many. Cap at N distinct buckets (e.g. 256) and coarsen to log-scale buckets beyond it; those triads are not beacons anyway. |
| Byte-size median, MAD, quartiles | Yes, via histogram | dict `bytes → count` | Same technique. Bucket bytes to 16-byte or 1 % bins to bound cardinality. |
| Prevalence (hosts per dst) | Yes | per-`dst_ip` set of internal `src_ip` | Bounded by internal host count, not by rows. |
| Timestamp sort | **No** | – | Requires sorted input or an external sort. Not doing this in-memory is the point. |

**Memory bound.** State is per triad, so memory scales with **distinct triads**, not rows. Tens of millions of flows
from a mid-size network can hold millions of triads; a naïve dict of full state per triad could reach gigabytes.
The standard fix is **two passes**: pass 1 keeps only a count per triad (one int each); pass 2 keeps full state only
for triads with `count ≥ min_conn`. This is still "never the whole file in memory" and still stdlib. A one-pass
approximation (count-min sketch for pass 1) is possible but is not worth the complexity for a toy.

**Stdlib fit.** `csv` for reading, `ipaddress` for the RFC 1918 "internal" test, `statistics.median` / `quantiles`
on expanded small histograms, `collections.Counter`. No third-party dependency needed.

## Q3 — False-positive sources and suppression

Benign periodic traffic named across sources
([Active Countermeasures](https://www.activecountermeasures.com/threat-hunting-false-positives/),
[Black Hills](https://www.blackhillsinfosec.com/detecting-malware-beacons-with-zeek-and-rita/),
[Decryption Digest](https://www.decryptiondigest.com/blog/how-to-detect-c2-beaconing-traffic-network-logs),
[GTK Cyber](https://gtkcyber.com/blog/hunting-c2-beaconing-python/)):

| Source | Typical signature in flow data | Suppression used by existing tools |
|---|---|---|
| NTP | `dst_port 123/udp`, small fixed size, ~every 15 min or faster | Safelist by port/destination (RITA whitelist import, AC-Hunter safelists). |
| OS / AV / browser update checks, telemetry | HTTPS to vendor CDNs, many internal hosts hit the same dst | **Prevalence**: RITA −15 % when ≥ 50 % of hosts talk to the dst; allowlist vendor ranges. |
| Monitoring heartbeats, SaaS keep-alives, CRL/OCSP | Regular, small, often to a handful of dsts | Same prevalence rule; analyst safelist; byte-size and count thresholds. |
| Scanners / chatty internal services | High count but irregular | Minimum-count gates alone are insufficient; require the regularity score too (zeek-quick's OR condition is the anti-pattern). |

Offline-compatible suppression flowtest can implement: (1) a **safelist file** of dst IPs / CIDRs / ports the
analyst maintains, (2) RITA's **prevalence modifier** computed from the CSV itself, (3) requiring the regularity
sub-score to carry the final score rather than count alone, (4) reporting the raw sub-scores so the analyst can see
*why* a triad scored. Nothing here needs DNS, GeoIP or a blocklist.

## Recommendation

Implement RITA v5's four-sub-score formula with equal weights, per triad, over a counting pre-pass plus one scoring
pass, with interval and size statistics computed from capped integer histograms. Default `min_conn` **20**
(zeek-quick / GTK consensus; RITA's 4 is tuned for a richer data model and produces noise on flow data). Apply the
prevalence ±15 % modifier and an optional safelist file. Emit score plus the four sub-scores, interval mode, size mode,
and connection count so results are explainable.

## Risks and unknowns, ranked

1. **Input not sorted by time.** Interval math is meaningless on unsorted rows. De-risk: state "sorted by `ts`" as an
   input requirement in the PRD and detect violations (out-of-order row → warn/abort), or provide a `sort` subcommand
   using an external merge sort on disk. Decision for Craig.
2. **Triad cardinality blows memory in pass 1.** A `dict[tuple, int]` with millions of keys is hundreds of MB in
   CPython. De-risk: key as a packed `bytes` (12 bytes for IPv4 pair + port); measure on a synthetic 10 M-row file
   in the first slice.
3. **Flow records vs connection records.** NetFlow exports may split one long connection into several flows or
   aggregate several into one, distorting intervals and sizes. De-risk: document the assumption "one row ≈ one
   connection"; consider collapsing rows within the same second per triad (RITA drops zero intervals for the same reason).
4. **Histogram capping changes the statistics for noisy triads.** Acceptable because those triads score low anyway,
   but the coarsening rule must be deterministic and tested. De-risk: property test that a capped histogram of a
   true beacon yields the same score as the uncapped one.
5. **Formula fidelity vs RITA is unverified.** The formulas above are read from source, but RITA's ClickHouse query
   may pre-filter (e.g. unique timestamps) in ways not visible in `beacons.go`. De-risk: cross-check one pair against
   `integration/get_beacon_info.py` if fidelity matters; otherwise state "RITA-inspired", not "RITA-compatible".

## What I need from Craig to finalise the recommendation

- Whether sorted input is a requirement or flowtest must sort (Risk 1).
- The definition of "internal" (RFC 1918 only, or a configurable CIDR list) since it gates which side is the beacon source.
- Whether the toy needs the histogram and duration sub-scores at all, or ts + ds is enough for v0.1.

## Open questions for Craig

1. Input contract: require `ts`-sorted CSV, or add a disk-backed sort? (Recommended: require sorted, detect and abort.)
2. Grouping: per `(src, dst, port)` triad like Flare, or per host pair like RITA? (Recommended: triad; port disambiguates NTP vs HTTPS to the same host.)
3. Scope for v0.1: all four sub-scores, or ts + ds only with hist/dur as a follow-up? (Recommended: all four; hist and dur are 24 ints each and cheap.)
4. Suppression: ship a default safelist (e.g. port 123) or start empty and let the analyst build it? (Recommended: empty file with commented examples; a default that hides NTP could also hide NTP-tunnelled C2.)
5. Output: ranked list with a `--min-score` default of 0.7, or everything above `min_conn`? (Recommended: ranked, default 0.7, matching RITA's "low" threshold.)

## Sources

- RITA source, `analysis/beacons.go` and `default_config.hjson`: https://github.com/activecm/rita
- RITA v4 formulas via KQL port: https://book.bluraven.io/threat-hunting-and-detection/command-and-control/implementing-rita-using-kql
- Active Countermeasures, beacon labs: https://activecm.github.io/threat-hunting-labs/beacons/
- Active Countermeasures, false positives: https://www.activecountermeasures.com/threat-hunting-false-positives/ (page blocked automated fetch; used search summary only)
- Black Hills, Zeek + RITA: https://www.blackhillsinfosec.com/detecting-malware-beacons-with-zeek-and-rita/ (blocked automated fetch; search summary only)
- zeek-quick: https://github.com/0xPersist/zeek-quick
- GTK Cyber, hunting C2 beaconing with Python: https://gtkcyber.com/blog/hunting-c2-beaconing-python/
- Flare: https://github.com/austin-taylor/flare and https://github.com/austin-taylor/flare/blob/master/flare/analytics/command_control.py
- QFunction, Zeek + math: https://qfunction.ai/blog/automated-threat-hunting-for-network-beacons-using-zeek-and-math
- Decryption Digest on C2 beaconing: https://www.decryptiondigest.com/blog/how-to-detect-c2-beaconing-traffic-network-logs (blocked automated fetch; search summary only)
- corelight/zeek-caldera-detector: https://github.com/corelight/zeek-caldera-detector
