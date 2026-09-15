"""Slice 2 acceptance: the Beacon score as a pure library (PRD 6.4, ADR 0001, eng-review F1/F2/F5).

Fixtures are built in-test from ordered timestamps and byte counts; there is no CSV and no CLI here.
"""

from __future__ import annotations

import random

import pytest

from flowtest.beacon import adjust_for_prevalence, score_tuple

HOUR = 3600
DAY = 24 * HOUR
FILE = (0, DAY)  # a 24 h file span: first ts 0, last ts 86400


def regular(count: int, interval: int, start: int = 0) -> list[int]:
    return [start + i * interval for i in range(count)]


def jittered_beacon(seed: int, start: int, count: int, interval: int = 60, jitter: int = 2):
    """A 60 s +/- 2 s beacon with small byte-size jitter, as the PRD's planted Tuple."""
    rng = random.Random(seed)
    ts, sizes, t = [], [], start
    for _ in range(count):
        ts.append(t)
        sizes.append(1000 + rng.randint(-30, 30))
        t += interval + rng.randint(-jitter, jitter)
    return ts, sizes


def browser(seed: int, count: int = 400):
    """Irregular Tuple spread across the day: random gaps and sizes, as a person browsing."""
    rng = random.Random(seed)
    ts, sizes, t = [], [], 0
    for _ in range(count):
        ts.append(t)
        sizes.append(rng.randint(200, 60_000))
        t += rng.randint(1, 400)
    assert t <= DAY
    return ts, sizes


# --- the flagship fixtures (PRD US-03, test cases 3, 11) --------------------------------------


def test_perfect_hourly_beacon_scores_exactly_one():
    # 24 flows one per hour, identical sizes, first and last flows are the file's first and last ts.
    ts = regular(24, HOUR)
    result = score_tuple(ts, [512] * 24, ts[0], ts[-1])
    assert result is not None
    assert (result.interval, result.size, result.histogram, result.duration) == (1.0, 1.0, 1.0, 1.0)
    assert result.score == 1.0
    assert result.median_interval == HOUR


def test_full_span_60s_beacon_scores_at_least_0_85():
    ts, sizes = jittered_beacon(seed=1, start=0, count=1440)
    result = score_tuple(ts, sizes, 0, ts[-1])
    assert result is not None
    assert result.score >= 0.85
    assert result.median_interval == 60


def test_thirty_flow_burst_in_a_day_is_scorable_but_loses_histogram_and_duration():
    # Same beacon, 30 flows (a 29-minute burst) starting two hours into a 24 h file (eng-review F1).
    ts, sizes = jittered_beacon(seed=1, start=2 * HOUR, count=30)
    result = score_tuple(ts, sizes, *FILE)
    assert result is not None
    assert result.histogram == 0.0 and result.duration == 0.0
    assert result.interval > 0.9 and result.size > 0.9
    # Documented outcome: a short burst tops out near 0.5 because half the score needs span coverage.
    # The exact value is seed-specific (other seeds land 0.44 to 0.49); it is pinned to catch formula drift.
    assert result.score == 0.485


def test_irregular_browser_tuple_scores_below_the_full_span_beacon():
    beacon_ts, beacon_sizes = jittered_beacon(seed=2, start=0, count=1440)
    beacon = score_tuple(beacon_ts, beacon_sizes, 0, DAY)
    web_ts, web_sizes = browser(seed=3)
    web = score_tuple(web_ts, web_sizes, 0, DAY)
    assert beacon is not None and web is not None
    assert web.score < beacon.score


# --- gate and guards (PRD 6.4, eng-review F2) --------------------------------------------------


def test_twelve_flows_in_the_same_second_are_not_scorable():
    assert score_tuple([100] * 12, [10] * 12, *FILE) is None


def test_zero_intervals_are_excluded_and_three_non_zero_intervals_is_the_gate():
    # 4 distinct seconds = 3 non-zero Intervals: scorable. Extra flows in the same second add nothing.
    assert score_tuple([0, 0, 0, 60, 120, 180], [1] * 6, *FILE) is not None
    assert score_tuple([0, 0, 0, 60, 120], [1] * 5, *FILE) is None


def test_equal_quartiles_give_skew_term_one_without_exception():
    # Every Interval is 5 s: Q3 - Q1 = 0, Bowley would be 0/0. Guard forces skew to 0, term to 1.
    ts = regular(9, 5)
    result = score_tuple(ts, [100] * 9, *FILE)
    assert result is not None
    assert result.interval == 1.0


def test_median_equal_to_a_quartile_forces_skew_to_zero():
    # Intervals 10 x5, 50 x4 (sorted): Q1 = Q2 = 10, Q3 = 50, Q3 - Q1 >= 10 but median == Q1 -> skew 0.
    intervals = [10, 10, 10, 10, 10, 50, 50, 50, 50]
    ts = [0]
    for gap in intervals:
        ts.append(ts[-1] + gap)
    result = score_tuple(ts, [100] * len(ts), *FILE)
    assert result is not None
    # skew term 1; dispersion: median 10, MAD 0 -> 1. Interval sub-score 1.
    assert result.interval == 1.0


def test_interval_sub_score_hand_computed():
    # Intervals [5, 10, 15, 20, 40, 60, 100]: exclusive quartiles land exactly on 10, 20, 60.
    # Bowley = (60 + 10 - 40) / 50 = 0.6 -> skew term 0.4. MAD = 15 -> dispersion (20 - 15) / 20 = 0.25.
    # Interval sub-score = (0.4 + 0.25) / 2 = 0.325.
    ts = [0, 5, 15, 30, 50, 90, 150, 250]
    result = score_tuple(ts, [100] * len(ts), *FILE)
    assert result is not None
    assert result.interval == pytest.approx(0.325)
    assert result.median_interval == 20


def test_size_dispersion_defaults_to_zero_when_median_size_is_below_one():
    # All byte counts 0: skew term 1 (equal quartiles), dispersion term 0 -> size sub-score 0.5.
    ts = regular(24, HOUR)
    result = score_tuple(ts, [0] * 24, ts[0], ts[-1])
    assert result is not None
    assert result.size == 0.5


def test_size_sub_score_hand_computed():
    # Byte counts sorted [5, 10, 15, 20, 40, 60, 100] over 7 hourly flows -> quartiles 10, 20, 60 as
    # in the interval fixture, so the same 0.325. Order of the sizes must not matter.
    ts = regular(7, HOUR)
    sizes = [100, 5, 60, 10, 40, 15, 20]
    result = score_tuple(ts, sizes, *FILE)
    assert result is not None
    assert result.size == pytest.approx(0.325)


# --- histogram and duration (PRD 6.4 bins, eng-review F2 bin edge) -----------------------------


def test_flow_at_the_last_timestamp_lands_in_bin_23_not_a_25th_bin():
    # 24 hourly flows spanning the file exactly: one per bin, so the histogram is perfectly flat.
    # Without the edge rule the last flow would fall off the end and the histogram would be 0.952.
    ts = regular(24, HOUR)
    result = score_tuple(ts, [1] * 24, ts[0], ts[-1])
    assert result is not None
    assert result.histogram == 1.0


def test_histogram_is_zero_when_coefficient_of_variation_exceeds_one():
    # 30 flows a minute apart inside one hour of a 24 h file: all in bin 2.
    ts = regular(30, 60, start=2 * HOUR)
    result = score_tuple(ts, [1] * 30, *FILE)
    assert result is not None
    assert result.histogram == 0.0


def test_histogram_partial_credit_hand_computed():
    # 12 flows in 12 distinct bins of a 24-bin day: counts are twelve 1s and twelve 0s.
    # mean 0.5, population sd 0.5, ratio 1 -> histogram 0 (ratio exactly 1 is not > 1, but 1 - 1 = 0).
    ts = [i * 2 * HOUR + 1 for i in range(12)]
    result = score_tuple(ts, [1] * 12, *FILE)
    assert result is not None
    assert result.histogram == 0.0
    # 16 flows in 16 distinct bins: mean 2/3, sd = sqrt(2/3 * 1/3) = 0.4714, ratio 0.7071 -> 0.2929.
    ts = [i * HOUR + 1 for i in range(16)]
    result = score_tuple(ts, [1] * 16, *FILE)
    assert result is not None
    assert result.histogram == pytest.approx(1 - (2 / 3 * 1 / 3) ** 0.5 / (2 / 3))


def test_twenty_four_consecutive_non_empty_bins_give_duration_one_never_two():
    ts = regular(24, HOUR)
    result = score_tuple(ts, [1] * 24, ts[0], ts[-1])
    assert result is not None
    assert result.duration == 1.0


def test_duration_is_zero_below_six_occupied_bins():
    # 5 hourly flows occupy 5 bins of a 24 h file: under the 6-bin gate.
    ts = regular(5, HOUR)
    result = score_tuple(ts, [1] * 5, *FILE)
    assert result is not None
    assert result.duration == 0.0


def test_duration_takes_the_larger_of_span_ratio_and_run_over_twelve():
    # 6 hourly flows: Tuple span 5 h / 24 h = 0.2083; run of 6 bins / 12 = 0.5 -> 0.5.
    ts = regular(6, HOUR)
    result = score_tuple(ts, [1] * 6, *FILE)
    assert result is not None
    assert result.duration == pytest.approx(0.5)
    # 6 flows spread across the whole day, 4 h apart: span 20 h / 24 h = 0.8333; run 1 / 12 -> 0.8333.
    ts = regular(6, 4 * HOUR)
    result = score_tuple(ts, [1] * 6, *FILE)
    assert result is not None
    assert result.duration == pytest.approx(20 / 24)


def test_sub_scores_are_clamped_and_final_is_the_rounded_mean():
    ts, sizes = jittered_beacon(seed=5, start=0, count=200)
    result = score_tuple(ts, sizes, 0, DAY)
    assert result is not None
    for sub in (result.interval, result.size, result.histogram, result.duration):
        assert 0.0 <= sub <= 1.0
    mean = (result.interval + result.size + result.histogram + result.duration) / 4
    assert result.score == round(mean, 3)


# --- input contract ----------------------------------------------------------------------------


def test_mismatched_lengths_are_rejected():
    with pytest.raises(ValueError):
        score_tuple([0, 60, 120, 180], [1, 1, 1], *FILE)


def test_timestamps_must_be_ordered():
    with pytest.raises(ValueError):
        score_tuple([0, 120, 60, 180], [1] * 4, *FILE)


def test_timestamps_must_lie_inside_the_file_span():
    with pytest.raises(ValueError):
        score_tuple([0, 60, 120, DAY + 1], [1] * 4, *FILE)


def test_empty_tuple_is_not_scorable():
    assert score_tuple([], [], *FILE) is None


# --- Prevalence adjustment (PRD 6.4, US-12, eng-review F5) -------------------------------------


def test_high_prevalence_lowers_the_score_and_floors_at_zero():
    assert adjust_for_prevalence(0.9, hosts_to_dst=60, internal_hosts_total=100).score == 0.75
    low = adjust_for_prevalence(0.1, hosts_to_dst=60, internal_hosts_total=100)
    assert low.score == 0.0 and low.applied and low.delta == -0.15


def test_low_prevalence_raises_the_score_and_caps_at_one():
    assert adjust_for_prevalence(0.5, hosts_to_dst=1, internal_hosts_total=100).score == 0.65
    high = adjust_for_prevalence(0.9, hosts_to_dst=1, internal_hosts_total=100)
    assert high.score == 1.0 and high.applied and high.delta == 0.15


def test_fewer_than_ten_internal_hosts_means_no_adjustment_and_not_applied():
    result = adjust_for_prevalence(0.5, hosts_to_dst=1, internal_hosts_total=2)
    assert result.score == 0.5 and not result.applied and result.delta == 0.0
    result = adjust_for_prevalence(0.5, hosts_to_dst=1, internal_hosts_total=9)
    assert not result.applied


def test_middling_prevalence_is_applied_but_changes_nothing():
    result = adjust_for_prevalence(0.5, hosts_to_dst=10, internal_hosts_total=100)
    assert result.score == 0.5 and result.applied and result.delta == 0.0


@pytest.mark.parametrize(
    ("hosts", "total", "delta"),
    [
        (2, 100, 0.15),  # exactly 2 %: low band is inclusive
        (3, 100, 0.0),  # 3 %: no band
        (49, 100, 0.0),  # 49 %: no band
        (50, 100, -0.15),  # exactly 50 %: high band is inclusive
        (1, 10, 0.0),  # 10 %, at the minimum denominator
        (5, 10, -0.15),  # 50 % of the minimum denominator
    ],
)
def test_prevalence_band_boundaries(hosts, total, delta):
    assert adjust_for_prevalence(0.5, hosts_to_dst=hosts, internal_hosts_total=total).delta == delta


def test_prevalence_result_stays_at_three_decimals():
    assert adjust_for_prevalence(0.487, hosts_to_dst=1, internal_hosts_total=100).score == 0.637


def test_prevalence_rejects_impossible_counts():
    with pytest.raises(ValueError):
        adjust_for_prevalence(0.5, hosts_to_dst=11, internal_hosts_total=10)
    with pytest.raises(ValueError):
        adjust_for_prevalence(0.5, hosts_to_dst=0, internal_hosts_total=10)


# --- verify-review edge cases (PR #24, R4 / R5) ---------------------------------------------------


def test_zero_length_file_span_is_not_scorable():
    # Every flow in the same second: no non-zero Interval, and no span to bin over.
    assert score_tuple([5, 5, 5, 5], [1, 1, 1, 1], 5, 5) is None


def test_timestamp_before_file_start_is_rejected():
    ts = regular(10, 60, start=100)
    with pytest.raises(ValueError, match="before the file span start"):
        score_tuple(ts, [1] * 10, 200, DAY)


def test_unordered_timestamps_name_the_offending_pair():
    with pytest.raises(ValueError, match="non-decreasing"):
        score_tuple([0, 60, 30, 90], [1] * 4, 0, DAY)


@pytest.mark.parametrize("span", [1, 5, 23, 25, 97, 86399, 86401, 10**9 + 7])
def test_last_timestamp_lands_in_bin_23_for_any_span(span):
    # Bin assignment is integer floor((ts - first) * 24 / span); a flow at exactly file_last must be in
    # bin 23, never a 25th bin, whether or not the span divides by 24.
    from flowtest.beacon import BINS, _bin_counts

    counts = _bin_counts([0, span], 0, span)
    assert len(counts) == BINS
    assert counts[0] == 1 and counts[BINS - 1] == 1


def test_no_adjustment_path_still_rounds_and_clamps():
    result = adjust_for_prevalence(0.98765, hosts_to_dst=1, internal_hosts_total=3)
    assert result == (0.988, False, 0.0)
    result = adjust_for_prevalence(1.2, hosts_to_dst=1, internal_hosts_total=3)
    assert result.score == 1.0
