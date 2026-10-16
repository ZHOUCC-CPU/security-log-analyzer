"""V1.0 controlled synthetic association performance benchmark.

Timing excludes dataset generation, file ingestion, warm-up,
and memory profiling. tracemalloc is not full-process RSS.
No production throughput or attack-detection claims are made.
"""

import argparse
import json
import math
import os
import platform
import statistics
import sys
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from generate_comparison_v09 import generate_expanded_dataset
from log_analyzer.three_source_v08 import (
    find_three_source_candidates,
)


def _validate_parameters(repeats, trials, window_seconds):
    if (
        not isinstance(repeats, (list, tuple))
        or not repeats
        or any(type(value) is not int or value < 1
               for value in repeats)
        or len(repeats) != len(set(repeats))
    ):
        raise ValueError(
            "repeats must contain unique positive integers"
        )

    if type(trials) is not int or trials < 1:
        raise ValueError("trials must be a positive integer")

    if (
        type(window_seconds) not in (int, float)
        or not math.isfinite(window_seconds)
        or window_seconds < 0
    ):
        raise ValueError(
            "window_seconds must be finite and nonnegative"
        )


def _pair_ids(candidates):
    return [
        tuple(candidate["event_ids"])
        for candidate in candidates
    ]


def run_benchmark(
    *,
    repeats=(1, 10, 50),
    trials=5,
    window_seconds=120,
):
    """Benchmark in-memory association on synthetic observations."""

    _validate_parameters(repeats, trials, window_seconds)

    rows = []

    for repeat in repeats:
        # Generation is outside all timed and memory measurements.
        dataset = generate_expanded_dataset(
            repeats=repeat,
            seed=20261011,
        )

        events = dataset["events"]
        mappings = dataset["host_mappings"]

        if (
            len(events) != 32 * repeat
            or len(mappings) != 16 * repeat
        ):
            raise RuntimeError(
                "Unexpected synthetic dataset dimensions"
            )

        # Warm-up: not included in timing.
        reference = find_three_source_candidates(
            events,
            mappings,
            window_seconds=window_seconds,
        )

        expected_ids = _pair_ids(reference)
        timings = []

        for _ in range(trials):
            start = time.perf_counter_ns()

            candidates = find_three_source_candidates(
                events,
                mappings,
                window_seconds=window_seconds,
            )

            duration_ns = time.perf_counter_ns() - start

            if _pair_ids(candidates) != expected_ids:
                raise RuntimeError(
                    "Candidate results changed between trials"
                )

            timings.append(duration_ns / 1_000_000)

        # Memory is measured in a separate association run.
        # This avoids mixing tracemalloc overhead into timings.
        if tracemalloc.is_tracing():
            raise RuntimeError(
                "tracemalloc is already active; "
                "cannot isolate the memory measurement"
            )

        tracemalloc.start()

        try:
            memory_candidates = find_three_source_candidates(
                events,
                mappings,
                window_seconds=window_seconds,
            )

            _, peak_bytes = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        if _pair_ids(memory_candidates) != expected_ids:
            raise RuntimeError(
                "Candidate results changed in memory trial"
            )

        rows.append({
            "repeats": repeat,
            "event_count": len(events),
            "host_mapping_count": len(mappings),
            "candidate_pair_count": len(reference),
            "timings_ms": timings,
            "median_ms": statistics.median(timings),
            "traced_peak_mib": peak_bytes / (1024 ** 2),
        })

    return {
        "benchmark_version": "v1.0",
        "dataset": "controlled_v0.9_synthetic",
        "seed": 20261011,
        "measurement_scope": "in_memory_association_only",
        "memory_metric": "tracemalloc_peak_mib",
        "memory_method": "separate_untimed_association_run",
        "trials": trials,
        "window_seconds": window_seconds,
        "python_version": platform.python_version(),
        "platform": platform.system(),
        "machine": platform.machine(),
        "logical_cpu_count": os.cpu_count(),
        "production_performance_claim": False,
        "limitations": [
            "Synthetic inputs are not representative of production.",
            "Timing excludes dataset generation, file ingestion, and report writing.",
            "tracemalloc peak excludes allocations outside Python tracking and is not process RSS.",
            "Operating-system scheduling and background load may affect timings.",
            "Candidate counts are not confirmed attacks or verified sessions.",
        ],
        "runs": rows,
    }


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Controlled V1.0 synthetic association benchmark"
        )
    )

    parser.add_argument(
        "--repeats",
        type=int,
        nargs="+",
        default=[1, 10, 50],
    )

    parser.add_argument(
        "--trials",
        type=int,
        default=5,
    )

    parser.add_argument(
        "--window-seconds",
        type=float,
        default=120,
    )

    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="New report path inside results/",
    )

    args = parser.parse_args()

    try:
        destination = args.output.resolve()
        results_dir = (ROOT / "results").resolve()

        if not destination.is_relative_to(results_dir):
            raise ValueError(
                "Benchmark output must be inside results/"
            )

        if destination.exists():
            raise FileExistsError(
                f"Output already exists: {destination}"
            )

        report = run_benchmark(
            repeats=args.repeats,
            trials=args.trials,
            window_seconds=args.window_seconds,
        )

        payload = (
            json.dumps(
                report,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            ) + "\n"
        ).encode("utf-8")

        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with destination.open("xb") as handle:
            handle.write(payload)

    except (ValueError, RuntimeError, OSError) as exc:
        parser.exit(1, f"ERROR: {exc}\n")

    print("[PASS] V1.0 benchmark completed")

    for row in report["runs"]:
        print(
            f"Events: {row['event_count']} | "
            f"Candidates: {row['candidate_pair_count']} | "
            f"Median: {row['median_ms']:.3f} ms | "
            f"Traced peak: {row['traced_peak_mib']:.3f} MiB"
        )

    print("Output:", args.output)


if __name__ == "__main__":
    main()
