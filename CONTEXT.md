# flowtest

Offline triage of NetFlow-style CSV exports for a security analyst: who talks most, which ports are in play,
and which internal hosts call out on a suspiciously regular schedule.

## Language

### Input

**Flow**:
One row of the input CSV: a summarised connection between a source and a destination with a timestamp,
protocol, destination port, byte count and packet count. One flow is treated as one connection.
_Avoid_: record, row (when the meaning is a parsed connection rather than a line of text), session

**Skipped row**:
An input line that fails to parse or violates the column contract. It is counted and reported, never fatal.
_Avoid_: bad row, error row, dropped row

**Internal host**:
An IP address inside the site's private ranges. By default RFC 1918, IPv4 loopback and link-local, and IPv6
unique-local, loopback and link-local; the analyst may replace the list per run.
_Avoid_: local host, inside host, private IP (as a synonym for the concept; RFC 1918 is only the default rule)

**External host**:
Any IP address that is not an Internal host.

### Analysis

**Tuple**:
The unit beacon scoring works on: one Internal host, one External host, one destination port and one
protocol. All flows from that source to that destination, port and protocol belong to the same Tuple; ICMP
Tuples use port 0.
_Avoid_: triad (RITA/Flare term), pair (which means source and destination only), connection key

**Out-of-order row**:
A Flow whose timestamp is earlier than the previous Flow of the same Tuple. Dropped from that Tuple's
statistics and counted; never fatal. Interleaving between different Tuples is not out of order.
_Avoid_: unsorted row, disorder

**Pair**:
A source host and a destination host regardless of port. Used by top-talkers, never by beacon scoring.

**Outbound flow**:
A Flow whose source is an Internal host and whose destination is an External host. Only Outbound flows are
candidates for beacon scoring.

**Interval**:
The elapsed seconds between two consecutive Flows of the same Tuple. Zero-second Intervals are ignored by
scoring.

**Beacon**:
A Tuple whose Outbound flows recur at regular Intervals, the pattern of malware checking in with a
command-and-control server. flowtest never declares a Tuple a Beacon; it ranks Tuples by Beacon score.
_Avoid_: C2 hit, callback, heartbeat (which is the benign look-alike)

**Beacon score**:
A number from 0.000 to 1.000, higher meaning more Beacon-like, formed from four equally weighted sub-scores
(Interval regularity, byte-size consistency, hourly-histogram shape, time-span coverage) and adjusted by
Prevalence. Follows RITA v5.
_Avoid_: confidence, probability, risk score

**Prevalence**:
The share of Internal hosts in the file that have at least one Flow to a given External host. High
Prevalence lowers a Tuple's Beacon score (shared services), very low Prevalence raises it.
_Avoid_: popularity, fan-in

**Top talker**:
A host or Pair ranked by total bytes, packets or Flow count over the whole file.

### Output

**Table output**:
The default human-readable, column-aligned report on stdout.

**JSON output**:
The machine-readable alternative: exactly one JSON object on stdout with `results` and `meta`.

## Example dialogue

> **Dev:** So a Beacon is any Tuple with more than ten flows?
> **Analyst:** No. Ten flows is the gate for scoring. A Beacon is what a high Beacon score suggests, and
> flowtest only ranks; I decide.
> **Dev:** And a Pair is the same as a Tuple without the port?
> **Analyst:** Yes, but Pairs are for top-talkers only. Beaconing is always per Tuple, because NTP and HTTPS to
> the same host are different stories.
> **Dev:** If half the office talks to the same External host every hour?
> **Analyst:** That is high Prevalence: probably an update server. The score comes down. One laptop alone
> calling a host every 60 seconds is low Prevalence, and it goes up.
