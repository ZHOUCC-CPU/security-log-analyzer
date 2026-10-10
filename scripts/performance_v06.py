
"""Reproducible processing performance benchmark for V0.6."""

import argparse
import gc
import json
import platform
import statistics
import sys
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from generate_dataset import generate
from log_analyzer.quality import assess_event_quality
from log_analyzer.correlation import correlate_events
from log_analyzer.detection import detect

PROTECTED_NET = "10.10.20.0/24"
UNTRUSTED_NET = "10.10.30.0/24"


def measure(events, expected_findings):
    """Measure the three processing stages on pre-generated data."""

    gc.collect()
    tracemalloc.start()

    try:
        start = time.perf_counter()

        quality = assess_event_quality(events)
        after_quality = time.perf_counter()

        correlation = correlate_events(events)
        after_correlation = time.perf_counter()

        detection = detect(
            correlation,
            PROTECTED_NET,
            UNTRUSTED_NET,
        )
        end = time.perf_counter()

        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    if quality["summary"]["records_with_issues"] != 0:
        raise AssertionError("Unexpected synthetic data quality issues")

    if correlation["summary"]["total_events"] != len(events):
        raise AssertionError("Incorrect correlation event count")

    findings = detection["summary"]["findings"]

    if findings != expected_findings:
        raise AssertionError(
            f"Expected {expected_findings} findings, got {findings}"
        )

    elapsed = end - start

    if elapsed <= 0:
        raise AssertionError("Invalid elapsed time")

    return {
        "quality_ms": round(
            (after_quality - start) * 1000, 6
        ),
        "correlation_ms": round(
            (after_correlation - after_quality) * 1000, 6
        ),
        "detection_ms": round(
            (end - after_correlation) * 1000, 6
        ),
        "total_ms": round(elapsed * 1000, 6),
        "throughput_events_per_second": round(
            len(events) / elapsed, 3
        ),
        "traced_peak_mib": round(
            peak / (1024 * 1024), 6
        ),
        "findings": findings,
    }


def run_benchmark(scales, trials, seed):
    if trials < 1 or not scales or any(n < 1 for n in scales):
        raise ValueError("Scales and trials must be positive")

    measurements = []

    for scale in scales:
        # Dataset construction is deliberately outside the timer.
        events, labels = generate(
            repeats=scale,
            seed=seed,
        )

        expected_findings = sum(
            row["behavior_label"] for row in labels
        )

        runs = [
            measure(events, expected_findings)
            for _ in range(trials)
        ]

        def middle(key):
            return round(
                statistics.median(row[key] for row in runs),
                6,
            )

        measurements.append({
            "repeats": scale,
            "cases": len(labels),
            "events": len(events),
            "expected_findings": expected_findings,
            "trials": runs,
            "median": {
                "quality_ms": middle("quality_ms"),
                "correlation_ms": middle("correlation_ms"),
                "detection_ms": middle("detection_ms"),
                "total_ms": middle("total_ms"),
                "throughput_events_per_second": middle(
                    "throughput_events_per_second"
                ),
                "traced_peak_mib": middle("traced_peak_mib"),
            },
        })

    return {
        "experiment": "v0.6_processing_performance",
        "dataset_type": "deterministic_synthetic",
        "seed": seed,
        "python_version": platform.python_version(),
        "operating_system": platform.system(),
        "machine_architecture": platform.machine(),
        "trials_per_scale": trials,
        "measurements": measurements,
        "methodology": [
            "Input generation excluded from measurement.",
            "Quality, correlation and detection measured together.",
            "Each trial is preceded by garbage collection.",
            "Timing uses wall-clock perf_counter.",
            "Reported aggregate values are medians.",
            "tracemalloc tracks Python allocations made during processing.",
            "Pre-existing input allocations are not included in the trace.",
            "Timing includes tracemalloc instrumentation overhead.",
            "All data and labels are synthetic.",
        ],
        "limitations": [
            "Not a production throughput benchmark.",
            "No concurrent ingestion or disk I/O is measured.",
            "No total-process RSS or system-wide memory is measured.",
            "Results depend on hardware and runtime conditions.",
            "Performance is not equivalent to detection accuracy.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument(
        "--scales",
        nargs="+",
        type=int,
        default=[10, 100, 500],
    )
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--seed", type=int, default=20261009)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "results/performance-v0.6.json",
    )

    args = parser.parse_args()

    report = run_benchmark(
        args.scales,
        args.trials,
        args.seed,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    print("\nV0.6 PROCESSING PERFORMANCE")
    print(f"Python: {report['python_version']}")
    print(f"OS: {report['operating_system']}")
    print()

    header = (
        f"{'Events':>9} "
        f"{'Total ms':>12} "
        f"{'Events/s':>13} "
        f"{'Peak MiB':>11}"
    )
    print(header)

    for row in report["measurements"]:
        m = row["median"]
        print(
            f"{row['events']:>9} "
            f"{m['total_ms']:>12.3f} "
            f"{m['throughput_events_per_second']:>13.1f} "
            f"{m['traced_peak_mib']:>11.3f}"
        )

    print(f"\nReport: {args.output}")


if __name__ == "__main__":
    main()
