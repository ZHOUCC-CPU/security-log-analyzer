
"""Regression tests for V0.6 processing performance evaluation."""

import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from generate_dataset import generate
from performance_v06 import measure, run_benchmark


class TestPerformanceV06(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.events, cls.labels = generate(
            repeats=1,
            seed=20261009,
        )

    def test_fixture_size(self):
        self.assertEqual(len(self.events), 21)
        self.assertEqual(len(self.labels), 11)
        self.assertEqual(
            sum(row["behavior_label"] for row in self.labels),
            3,
        )

    def test_measure_returns_expected_findings(self):
        result = measure(self.events, expected_findings=3)

        self.assertEqual(result["findings"], 3)
        self.assertGreater(result["total_ms"], 0)
        self.assertGreater(
            result["throughput_events_per_second"], 0
        )
        self.assertGreaterEqual(result["traced_peak_mib"], 0)

    def test_measure_does_not_mutate_input(self):
        original = copy.deepcopy(self.events)

        measure(self.events, expected_findings=3)

        self.assertEqual(self.events, original)

    def test_incorrect_finding_count_rejected(self):
        with self.assertRaises(AssertionError):
            measure(self.events, expected_findings=4)

    def test_single_scale_counts(self):
        result = run_benchmark(
            scales=[1],
            trials=1,
            seed=20261009,
        )

        row = result["measurements"][0]

        self.assertEqual(row["events"], 21)
        self.assertEqual(row["cases"], 11)
        self.assertEqual(row["expected_findings"], 3)
        self.assertEqual(len(row["trials"]), 1)

    def test_multiple_scales(self):
        result = run_benchmark(
            scales=[1, 2],
            trials=1,
            seed=20261009,
        )

        rows = result["measurements"]

        self.assertEqual(
            [row["events"] for row in rows],
            [21, 42],
        )
        self.assertEqual(
            [row["expected_findings"] for row in rows],
            [3, 6],
        )

    def test_repeated_trials(self):
        result = run_benchmark(
            scales=[1],
            trials=3,
            seed=20261009,
        )

        row = result["measurements"][0]
        self.assertEqual(len(row["trials"]), 3)

        values = [
            trial["total_ms"]
            for trial in row["trials"]
        ]

        self.assertGreaterEqual(
            row["median"]["total_ms"],
            min(values),
        )
        self.assertLessEqual(
            row["median"]["total_ms"],
            max(values),
        )

    def test_median_aggregation(self):
        trials = []

        for number in (30.0, 10.0, 20.0):
            trials.append({
                "quality_ms": number / 4,
                "correlation_ms": number / 2,
                "detection_ms": number / 4,
                "total_ms": number,
                "throughput_events_per_second": number * 10,
                "traced_peak_mib": number / 10,
                "findings": 3,
            })

        with patch(
            "performance_v06.measure",
            side_effect=trials,
        ):
            result = run_benchmark(
                scales=[1],
                trials=3,
                seed=20261009,
            )

        median = result["measurements"][0]["median"]

        self.assertEqual(median["total_ms"], 20.0)
        self.assertEqual(
            median["throughput_events_per_second"],
            200.0,
        )
        self.assertEqual(
            median["traced_peak_mib"],
            2.0,
        )

    def test_invalid_scales(self):
        for scales in ([], [0], [-1], [1, 0]):
            with self.subTest(scales=scales):
                with self.assertRaises(ValueError):
                    run_benchmark(
                        scales=scales,
                        trials=1,
                        seed=20261009,
                    )

    def test_invalid_trials(self):
        for count in (0, -1):
            with self.subTest(trials=count):
                with self.assertRaises(ValueError):
                    run_benchmark(
                        scales=[1],
                        trials=count,
                        seed=20261009,
                    )


if __name__ == "__main__":
    unittest.main()
