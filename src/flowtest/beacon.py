"""Beacon score: RITA v5's four sub-scores plus the Prevalence adjustment (PRD 6.4, ADR 0001).

Pure functions over one Tuple's ordered timestamps and byte counts. No I/O, no CLI; the `beacons`
command groups flows into Tuples, drops Out-of-order rows and applies `--min-flows` before calling in.
Every guard below is RITA's and part of the requirement (eng-review F2), not an implementation choice.
"""

from __future__ import annotations

import statistics
from collections.abc import Sequence
from itertools import pairwise
from typing import NamedTuple

BINS = 24  # hourly histogram over the file span, whatever the span's length
MIN_INTERVALS = 3  # non-zero Intervals needed before a Tuple is scorable
MIN_OCCUPIED_BINS = 6  # duration coverage counts only when the Tuple appears in this many bins
RUN_FULL_CREDIT = 12  # a run of this many consecutive non-empty bins is full duration credit
SKEW_MIN_SPREAD = 10  # Bowley skew is meaningless when Q3 - Q1 is below this
PREVALENCE_MIN_HOSTS = 10  # denominator below this: no adjustment (eng-review F5)
PREVALENCE_DELTA = 0.15
LOW_PREVALENCE_PERCENT = 2  # share <= 2 %: rare destination, score goes up
HIGH_PREVALENCE_PERCENT = 50  # share >= 50 %: shared service, score goes down


class BeaconScore(NamedTuple):
    """The four sub-scores, each in [0, 1], their mean rounded to 3 dp, and the median Interval."""

    interval: float
    size: float
    histogram: float
    duration: float
    score: float
    median_interval: float


class PrevalenceResult(NamedTuple):
    """`applied` is whether the rule was in force (enough Internal hosts); `delta` is what it did."""

    score: float
    applied: bool
    delta: float


def _clamp(value: float) -> float:
    return min(1.0, max(0.0, value))


def _skew_term(values: Sequence[int]) -> float:
    """1 - |Bowley skewness|, with Bowley forced to 0 when the quartiles cannot support it."""
    q1, q2, q3 = statistics.quantiles(values, n=4, method="exclusive")
    spread = q3 - q1
    if spread < SKEW_MIN_SPREAD or q2 == q1 or q2 == q3:
        return 1.0
    bowley = (q3 + q1 - 2 * q2) / spread
    return 1.0 - abs(bowley)


def _dispersion_term(values: Sequence[int], median: float, *, default: float) -> float:
    """(median - MAD) / median, floored at 0; `default` when the median is below 1.

    For Intervals the default branch is unreachable with whole-second timestamps (a non-zero Interval
    is at least 1), and exists for formula fidelity only. It is reachable for byte sizes.
    """
    if median < 1:
        return default
    mad = statistics.median(abs(v - median) for v in values)
    return max(0.0, (median - mad) / median)


def _consistency(values: Sequence[int], *, dispersion_default: float) -> tuple[float, float]:
    """Sub-scores 1 and 2 share this shape. Returns (sub-score, median)."""
    median = statistics.median(values)
    skew = _skew_term(values)
    dispersion = _dispersion_term(values, median, default=dispersion_default)
    return _clamp((skew + dispersion) / 2), median


def _bin_counts(timestamps: Sequence[int], file_first: int, file_last: int) -> list[int]:
    """24 equal bins over [file_first, file_last]; a flow at exactly file_last goes in bin 23."""
    span = file_last - file_first
    counts = [0] * BINS
    for ts in timestamps:
        index = (ts - file_first) * BINS // span if span else 0
        counts[min(index, BINS - 1)] += 1
    return counts


def _histogram_score(counts: Sequence[int]) -> float:
    mean = statistics.fmean(counts)
    ratio = statistics.pstdev(counts) / mean
    return 0.0 if ratio > 1 else _clamp(1.0 - ratio)


def _longest_run(counts: Sequence[int]) -> int:
    longest = current = 0
    for count in counts:
        current = current + 1 if count else 0
        longest = max(longest, current)
    return longest


def _duration_score(counts: Sequence[int], tuple_span: int, file_span: int) -> float:
    if sum(1 for c in counts if c) < MIN_OCCUPIED_BINS:
        return 0.0
    span_ratio = min(1.0, tuple_span / file_span) if file_span else 0.0
    run_ratio = min(1.0, _longest_run(counts) / RUN_FULL_CREDIT)
    return _clamp(max(span_ratio, run_ratio))


def _check_inputs(timestamps: Sequence[int], sizes: Sequence[int], file_first: int, file_last: int) -> None:
    if len(timestamps) != len(sizes):
        raise ValueError(f"{len(timestamps)} timestamps but {len(sizes)} byte counts")
    if file_last < file_first:
        raise ValueError(f"file span ends ({file_last}) before it starts ({file_first})")
    if timestamps and timestamps[0] < file_first:
        raise ValueError(f"first timestamp {timestamps[0]} is before the file span start {file_first}")
    for a, b in pairwise(timestamps):
        if b < a:
            raise ValueError(f"timestamps must be in non-decreasing order ({b} follows {a})")
    if timestamps and timestamps[-1] > file_last:
        raise ValueError(f"last timestamp {timestamps[-1]} is after the file span end {file_last}")


def score_tuple(
    timestamps: Sequence[int], sizes: Sequence[int], file_first: int, file_last: int
) -> BeaconScore | None:
    """Score one Tuple. None means not scorable (fewer than 3 non-zero Intervals).

    `timestamps` are the Tuple's flow timestamps in order as whole epoch seconds (`int`, as the reader
    emits them; floats are not supported), `sizes` the matching byte counts, and [file_first, file_last]
    is the whole file's time span. Raises ValueError on inputs that break the contract: unordered
    timestamps, timestamps outside the span, mismatched lengths.
    """
    _check_inputs(timestamps, sizes, file_first, file_last)
    intervals = [b - a for a, b in pairwise(timestamps) if b != a]
    if len(intervals) < MIN_INTERVALS:
        return None

    interval_score, median_interval = _consistency(intervals, dispersion_default=1.0)
    size_score, _ = _consistency(sizes, dispersion_default=0.0)
    counts = _bin_counts(timestamps, file_first, file_last)
    histogram_score = _histogram_score(counts)
    duration_score = _duration_score(counts, timestamps[-1] - timestamps[0], file_last - file_first)

    final = round((interval_score + size_score + histogram_score + duration_score) / 4, 3)
    return BeaconScore(interval_score, size_score, histogram_score, duration_score, final, median_interval)


def adjust_for_prevalence(score: float, *, hosts_to_dst: int, internal_hosts_total: int) -> PrevalenceResult:
    """Apply the Prevalence rule to a Beacon score.

    Prevalence = hosts_to_dst / internal_hosts_total. Only in force when the total is at least 10:
    +0.15 at or below 2 %, -0.15 at or above 50 %, result clamped to [0, 1] and kept at 3 dp.
    """
    if hosts_to_dst < 1 or hosts_to_dst > internal_hosts_total:
        raise ValueError(
            f"hosts_to_dst must be in 1..internal_hosts_total, got {hosts_to_dst}/{internal_hosts_total}"
        )
    if internal_hosts_total < PREVALENCE_MIN_HOSTS:
        # Same post-condition as the in-force path: clamped, 3 dp.
        return PrevalenceResult(round(_clamp(score), 3), False, 0.0)
    # Integer comparisons: hosts / total <= 2 % is hosts * 100 <= total * 2, exactly at the boundary.
    if hosts_to_dst * 100 <= internal_hosts_total * LOW_PREVALENCE_PERCENT:
        delta = PREVALENCE_DELTA
    elif hosts_to_dst * 100 >= internal_hosts_total * HIGH_PREVALENCE_PERCENT:
        delta = -PREVALENCE_DELTA
    else:
        delta = 0.0
    return PrevalenceResult(round(_clamp(score + delta), 3), True, delta)
