"""Issue #29: bounded-memory scoring from reduced per-Tuple state (PRD 6.4 and 10, ADR 0001).

`TupleAccumulator` is what the `beacons` command feeds one flow at a time in pass 2; `score_state`
applies the PRD 6.4 formula to the state it yields. `score_tuple` stays exact and both must agree.
"""

from __future__ import annotations

import random
import time

import pytest

from flowtest.beacon import (
    BINS,
    RESERVOIR_SIZE,
    BeaconScore,
    TupleAccumulator,
    TupleState,
    score_state,
    score_tuple,
)

HOUR = 3600
DAY = 24 * HOUR
FILE = (0, DAY)
KEY = ("10.0.0.5", "203.0.113.9", 443, "tcp")


def regular(count: int, interval: int, start: int = 0) -> list[int]:
    return [start + i * interval for i in range(count)]


def jittered_beacon(seed: int, start: int, count: int, interval: int = 60, jitter: int = 2):
    """Same shape as tests/test_beacon.py: a 60 s +/- 2 s beacon with small byte-size jitter."""
    rng = random.Random(seed)
    ts, sizes, t = [], [], start
    for _ in range(count):
        ts.append(t)
        sizes.append(1000 + rng.randint(-30, 30))
        t += interval + rng.randint(-jitter, jitter)
    return ts, sizes


def browser(seed: int, count: int = 400):
    rng = random.Random(seed)
    ts, sizes, t = [], [], 0
    for _ in range(count):
        ts.append(t)
        sizes.append(rng.randint(200, 60_000))
        t += rng.randint(1, 400)
    return ts, sizes


def accumulate(ts, sizes, file_first, file_last, key=KEY, **kwargs) -> TupleState:
    acc = TupleAccumulator(key, file_first, file_last, **kwargs)
    for t, s in zip(ts, sizes, strict=True):
        acc.add(t, s)
    return acc.state()


# --- lockstep with the full-array function (AC 1) -----------------------------------------------

FIXTURES = {
    "perfect_hourly": (regular(24, HOUR), [512] * 24, 0, 23 * HOUR),
    "thirty_flow_burst": (*jittered_beacon(seed=1, start=2 * HOUR, count=30), *FILE),
    "browser": (*browser(seed=3), *FILE),
    "same_second_x12": ([100] * 12, [10] * 12, *FILE),
    "three_intervals_gate": ([0, 0, 0, 60, 120, 180], [1] * 6, *FILE),
    "two_intervals_gate": ([0, 0, 0, 60, 120], [1] * 5, *FILE),
    "equal_quartiles": (regular(9, 5), [100] * 9, *FILE),
    "median_equals_quartile": ([0, 10, 20, 30, 40, 50, 100, 150, 200, 250], [100] * 10, *FILE),
    "interval_hand_computed": ([0, 5, 15, 30, 50, 90, 150, 250], [100] * 8, *FILE),
    "zero_sizes": (regular(24, HOUR), [0] * 24, 0, 23 * HOUR),
    "size_hand_computed": (regular(7, HOUR), [100, 5, 60, 10, 40, 15, 20], *FILE),
    "one_hour_burst": (regular(30, 60, start=2 * HOUR), [1] * 30, *FILE),
    "twelve_bins": ([i * 2 * HOUR + 1 for i in range(12)], [1] * 12, *FILE),
    "sixteen_bins": ([i * HOUR + 1 for i in range(16)], [1] * 16, *FILE),
    "five_bins": (regular(5, HOUR), [1] * 5, *FILE),
    "six_hourly": (regular(6, HOUR), [1] * 6, *FILE),
    "six_spread": (regular(6, 4 * HOUR), [1] * 6, *FILE),
    "jittered_200": (*jittered_beacon(seed=5, start=0, count=200), 0, DAY),
    "empty": ([], [], *FILE),
    "zero_span": ([5, 5, 5, 5], [1] * 4, 5, 5),
}


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_reduced_state_matches_full_array_on_every_library_fixture(name):
    ts, sizes, first, last = FIXTURES[name]
    assert len(ts) <= RESERVOIR_SIZE
    expected = score_tuple(ts, sizes, first, last)
    actual = score_state(accumulate(ts, sizes, first, last))
    assert actual == expected


def test_score_state_returns_a_beacon_score():
    ts = regular(24, HOUR)
    result = score_state(accumulate(ts, [512] * 24, ts[0], ts[-1]))
    assert isinstance(result, BeaconScore)
    assert result.score == 1.0 and result.median_interval == HOUR


# --- sampling above the reservoir size (AC 2) ---------------------------------------------------


def ten_thousand_flow_beacon():
    # A 24 h beacon every 8.64 s +/- 1 s: 10 000 flows, ten times the reservoir.
    rng = random.Random(29)
    ts, sizes, t = [], [], 0
    for _ in range(10_000):
        ts.append(t)
        sizes.append(4096 + rng.randint(-100, 100))
        t += 8 + rng.randint(0, 1)
    return ts, sizes, 0, ts[-1]


def test_ten_thousand_flow_beacon_scores_within_0_02_of_the_exact_score():
    ts, sizes, first, last = ten_thousand_flow_beacon()
    exact = score_tuple(ts, sizes, first, last)
    sampled = score_state(accumulate(ts, sizes, first, last))
    assert exact is not None and sampled is not None
    assert abs(sampled.score - exact.score) <= 0.02
    # Bins, first/last and flow count are exact, so these two sub-scores never differ.
    assert sampled.histogram == exact.histogram
    assert sampled.duration == exact.duration


def test_flagship_1440_flow_beacon_is_sampled_and_still_scores_at_least_0_85():
    # The PRD's planted Tuple has 1440 flows, just over the reservoir, so it is the first sampled case.
    ts, sizes = jittered_beacon(seed=1, start=0, count=1440)
    exact = score_tuple(ts, sizes, 0, ts[-1])
    sampled = score_state(accumulate(ts, sizes, 0, ts[-1]))
    assert exact is not None and sampled is not None
    assert sampled.score >= 0.85 and sampled.median_interval == 60
    assert abs(sampled.score - exact.score) <= 0.02


def test_sampling_is_deterministic_for_the_same_tuple_key():
    ts, sizes, first, last = ten_thousand_flow_beacon()
    one = accumulate(ts, sizes, first, last)
    two = accumulate(ts, sizes, first, last)
    assert one == two
    assert score_state(one) == score_state(two)


def test_different_tuple_keys_draw_different_samples():
    ts, sizes, first, last = ten_thousand_flow_beacon()
    one = accumulate(ts, sizes, first, last, key=KEY)
    other = accumulate(ts, sizes, first, last, key=("10.0.0.6", "203.0.113.9", 443, "tcp"))
    assert one.intervals != other.intervals
    assert one.sizes != other.sizes


def test_seed_does_not_depend_on_process_hash_randomisation():
    # str keys hash differently per process; the reservoir must not. A literal pins the sample, so a
    # regression to hash()-based seeding (which would still agree with itself within one process) fails.
    ts = regular(50, 60)
    state = accumulate(ts, list(range(50)), 0, DAY, key="pinned", capacity=5)
    assert state.sizes == [22, 12, 40, 35, 4]


def test_pinned_sample_survives_a_different_hash_seed_in_a_subprocess():
    import subprocess
    import sys

    code = (
        "from flowtest.beacon import TupleAccumulator\n"
        "acc = TupleAccumulator('pinned', 0, 86400, capacity=5)\n"
        "for i in range(50): acc.add(i * 60, i)\n"
        "print(acc.state().sizes)"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True,
                         env={"PYTHONHASHSEED": "12345", "PATH": ""})  # fmt: skip
    assert out.stdout.strip() == "[22, 12, 40, 35, 4]"


# --- bounded state and speed (AC 3) --------------------------------------------------------------


def test_hundred_thousand_flows_keep_the_state_bounded_and_fast():
    rng = random.Random(7)
    acc = TupleAccumulator(KEY, 0, 200_000)
    started = time.perf_counter()
    t = 0
    for _ in range(100_000):
        acc.add(t, rng.randint(100, 2000))
        t += rng.randint(1, 2)
    elapsed = time.perf_counter() - started
    state = acc.state()
    assert len(state.intervals) == RESERVOIR_SIZE == 1000
    assert len(state.sizes) == RESERVOIR_SIZE
    assert len(state.bins) == BINS == 24
    assert (state.first, state.last, state.flows) == (0, acc.last, 100_000)
    assert elapsed < 3.0, (
        f"100k flows took {elapsed:.2f}s"
    )  # ~0.1 s locally; wide margin for loaded CI runners


def test_reservoir_holds_everything_until_it_is_full_then_stays_at_capacity():
    acc = TupleAccumulator(KEY, 0, DAY, capacity=4)
    for i, t in enumerate(regular(4, 60)):
        acc.add(t, 100 + i)
    state = acc.state()
    assert state.sizes == [100, 101, 102, 103]
    assert state.intervals == [60, 60, 60]
    acc.add(240, 104)
    acc.add(300, 105)
    state = acc.state()
    assert len(state.sizes) == 4 and set(state.sizes) <= {100, 101, 102, 103, 104, 105}
    assert len(state.intervals) == 4 and set(state.intervals) == {60}


def test_reservoir_sample_is_unbiased_over_a_ramp():
    # Sizes 0..9999 in order: a fair sample has mean near 5000; keeping the first or last 1000 would not.
    ts = regular(10_000, 10)
    state = accumulate(ts, list(range(10_000)), 0, ts[-1])
    mean = sum(state.sizes) / len(state.sizes)
    assert 4000 < mean < 6000
    assert min(state.sizes) < 1000 and max(state.sizes) >= 9000


# --- zero Intervals and the gate (AC 4, AC 5) ----------------------------------------------------


def test_zero_intervals_are_kept_out_of_the_sample_but_counted_as_flows():
    acc = TupleAccumulator(KEY, *FILE)
    for t in (0, 0, 0, 60, 60, 120, 180):
        acc.add(t, 1)
    state = acc.state()
    assert state.intervals == [60, 60, 60]
    assert state.flows == 7
    assert len(state.sizes) == 7
    assert sum(state.bins) == 7


def test_gate_uses_the_true_count_of_non_zero_intervals_not_the_sample():
    acc = TupleAccumulator(KEY, *FILE, capacity=3)
    for t in [0] * 250 + [60] * 250 + [120]:
        acc.add(t, 1)
    state = acc.state()
    assert state.flows == 501 and state.nonzero_intervals == 2
    assert len(state.sizes) == 3  # the sample is full, yet the true Interval count says: not scorable
    assert score_state(state) is None
    acc.add(180, 1)
    state = acc.state()
    assert state.nonzero_intervals == 3 and len(state.intervals) == 3
    assert score_state(state) is not None


def test_capacity_below_the_gate_is_rejected():
    with pytest.raises(ValueError, match="capacity"):
        TupleAccumulator(KEY, *FILE, capacity=2)


def test_two_non_zero_intervals_among_five_hundred_zero_ones_is_not_scorable():
    ts = [0] * 250 + [60] * 250 + [120] * 3
    assert score_state(accumulate(ts, [1] * len(ts), *FILE)) is None
    assert score_tuple(ts, [1] * len(ts), *FILE) is None


def test_empty_accumulator_is_not_scorable_and_has_no_span():
    acc = TupleAccumulator(KEY, *FILE)
    state = acc.state()
    assert state.flows == 0 and state.intervals == [] and state.sizes == []
    assert score_state(state) is None


# --- median from the sample and state shape -------------------------------------------------------


def test_median_interval_is_reported_from_the_sample():
    ts, sizes, first, last = ten_thousand_flow_beacon()
    state = accumulate(ts, sizes, first, last)
    result = score_state(state)
    assert result is not None
    assert result.median_interval in (8, 8.5, 9)
    import statistics

    assert result.median_interval == statistics.median(state.intervals)


def test_state_carries_tuple_span_flow_count_and_file_span():
    ts = regular(10, HOUR, start=HOUR)
    state = accumulate(ts, [1] * 10, *FILE)
    assert (state.first, state.last, state.flows) == (HOUR, 10 * HOUR, 10)
    assert (state.file_first, state.file_last) == FILE
    assert state.nonzero_intervals == 9


# --- input contract, same as score_tuple ---------------------------------------------------------


def test_accumulator_rejects_out_of_order_timestamps():
    acc = TupleAccumulator(KEY, *FILE)
    acc.add(120, 1)
    with pytest.raises(ValueError, match="non-decreasing"):
        acc.add(60, 1)


def test_accumulator_rejects_timestamps_outside_the_file_span():
    acc = TupleAccumulator(KEY, 100, DAY)
    with pytest.raises(ValueError, match="before the file span start"):
        acc.add(50, 1)
    with pytest.raises(ValueError, match="after the file span end"):
        acc.add(DAY + 1, 1)


def test_accumulator_rejects_an_inverted_file_span():
    with pytest.raises(ValueError, match="ends"):
        TupleAccumulator(KEY, DAY, 0)


def test_accumulator_exposes_the_last_timestamp_for_order_checks():
    # The beacons command decides what an Out-of-order row is by comparing with the previous flow.
    acc = TupleAccumulator(KEY, *FILE)
    assert acc.last is None
    acc.add(60, 1)
    assert acc.last == 60


# --- memory: the reason this API exists (review F1/F2) --------------------------------------------


def test_accumulator_costs_about_a_kilobyte_not_four():
    """The reference file has ~330 k gate-passing Tuples; at 4.3 KB each (an eager Random per
    accumulator) pass 2 alone was 1.4 GB. Lazy RNG + array storage + __slots__ must keep a 16-flow
    accumulator well under 2 KB, so 330 k of them stay under ~600 MB."""
    import tracemalloc

    tracemalloc.start()
    try:
        accs = []
        for i in range(2000):
            acc = TupleAccumulator(("10.0.0.1", "203.0.113.9", 443, "tcp", i), 0, DAY)
            for k in range(16):
                acc.add(k * 60, 100 + k)
            accs.append(acc)
        current, _ = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    per_accumulator = current / len(accs)
    assert per_accumulator < 2000, f"{per_accumulator:.0f} bytes per 16-flow accumulator"


def test_random_generator_is_created_only_when_a_reservoir_overflows():
    acc = TupleAccumulator(KEY, 0, DAY, capacity=5)
    for i in range(5):
        acc.add(i * 60, i)
    assert acc._rng is None
    acc.add(5 * 60, 5)
    assert acc._rng is not None


@pytest.mark.parametrize("span", [1, 5, 23, 25, 97, 86399, 86401, 10**9 + 7])
def test_accumulator_bins_match_the_full_array_path_for_awkward_spans(span):
    ts = sorted({0, span // 3, span // 2, (2 * span) // 3, span})
    sizes = [100] * len(ts)
    exact = score_tuple(ts, sizes, 0, span)
    sampled = score_state(accumulate(ts, sizes, 0, span))
    assert exact == sampled
    state = accumulate(ts, sizes, 0, span)
    assert state.bins[23] >= 1 and sum(state.bins) == len(ts)


def test_contract_errors_name_the_timestamp_not_first_or_last():
    acc = TupleAccumulator(KEY, 100, DAY)
    acc.add(100, 1)
    with pytest.raises(ValueError, match="^timestamp 50 is before the file span start 100$"):
        acc.add(50, 1)
    with pytest.raises(ValueError, match="^timestamp 90000 is after the file span end 86400$"):
        acc.add(90000, 1)
