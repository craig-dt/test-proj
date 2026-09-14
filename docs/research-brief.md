# Research brief — flowtest

**Date:** 2026-09-14 · **Stage:** research · **Time box:** ~15 minutes of research · **Owner:** Craig

## Objective

Pick the beacon-scoring method flowtest will implement, so the PRD can state acceptance criteria for
"beacon detection" as a formula rather than a vibe. Top talkers and top ports are counting problems and are
not researched.

## Key questions to answer

1. **How do existing tools score beaconing?** For RITA (Active Countermeasures) and the Zeek ecosystem
   (Zeek beacon packages, Corelight/others): which signals they use (interval regularity, payload-size
   consistency, connection count, time-span coverage), how each signal becomes a sub-score, and how sub-scores
   combine into one number. Exact formulas where published.
2. **Which of those signals can be computed in a single streaming pass with bounded memory**, given a
   NetFlow-style CSV (`ts, src_ip, dst_ip, dst_port, proto, bytes, packets`) of tens of millions of rows and
   stdlib-only Python? Which signals require sorting or a second pass, and what is the cheapest faithful
   approximation for those?
3. **What are the known false-positive sources** (NTP, OS/AV update checkers, monitoring heartbeats, keep-alives)
   and how do existing tools suppress or down-weight them without external lookups?

## Constraints

- Local, offline Python CLI. Stdlib preferred; a third-party dependency must be justified per use.
- Input is only the 7-column CSV above. Files may be tens of millions of rows; the whole file must never be
  in memory.
- Toy project: research fits in ~15 minutes; brief stays at 3 questions.

## Exit criteria

Research is done when `docs/research.md`:

- names **one** scoring formula to adopt, with each sub-score and weight spelled out;
- states, per signal, whether it is computable in one streaming pass with bounded memory, and the
  approximation used if not;
- lists the known false-positive sources and the suppression approach for each;
- cites sources and flags anything the sources leave unspecified.

## Out of scope

- Non-CSV inputs (pcap, Zeek logs, IPFIX).
- Threat-intel, DNS, GeoIP, or blocklist enrichment of any kind.
- ML / anomaly-detection models; statistical scoring only.
- Performance benchmarking of Python against DuckDB, polars, Rust, awk, etc. Stdlib is a given.
