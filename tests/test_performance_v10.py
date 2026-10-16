"""Tests for the V1.0 controlled association benchmark."""

import hashlib
import statistics
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from benchmark_performance_v10 import run_benchmark


class TestPerformanceV10(unittest.TestCase):

    def test_single_scale_counts_and_timings(self):
        report = run_benchmark(
            repeats=(1,),
            trials=2,
        )

        self.assertEqual(report["benchmark_version"], "v1.0")
        self.assertEqual(report["trials"], 2)

        self.assertEqual(len(report["runs"]), 1)

        row = report["runs"][0]

        self.assertEqual(row["repeats"], 1)
        self.assertEqual(row["event_count"], 32)
        self.assertEqual(row["host_mapping_count"], 16)
        self.assertEqual(row["candidate_pair_count"], 6)

        self.assertEqual(len(row["timings_ms"]), 2)

        for duration in row["timings_ms"]:
            self.assertGreater(duration, 0)
            self.assertLess(duration, float("inf"))

        self.assertEqual(
            row["median_ms"],
            statistics.median(row["timings_ms"]),
        )

    def test_multiple_scales_preserve_expected_counts(self):
        report = run_benchmark(
            repeats=(1, 2),
            trials=1,
        )

        rows = report["runs"]

        self.assertEqual(len(rows), 2)

        actual = [
            (
                row["event_count"],
                row["host_mapping_count"],
                row["candidate_pair_count"],
            )
            for row in rows
        ]

        self.assertEqual(
            actual,
            [
                (32, 16, 6),
                (64, 32, 12),
            ],
        )

    def test_scope_and_memory_are_explicit(self):
        report = run_benchmark(
            repeats=(1,),
            trials=1,
        )

        self.assertEqual(
            report["measurement_scope"],
            "in_memory_association_only",
        )

        self.assertEqual(
            report["memory_metric"],
            "tracemalloc_peak_mib",
        )

        self.assertIs(
            report["production_performance_claim"],
            False,
        )

        self.assertGreater(
            report["runs"][0]["traced_peak_mib"],
            0,
        )

        notes = " ".join(report["limitations"]).lower()

        self.assertIn("synthetic", notes)
        self.assertIn("rss", notes)
        self.assertIn("generation", notes)

    def test_invalid_repeats_are_rejected(self):
        invalid = (
            (),
            (0,),
            (-1,),
            (1, 1),
            (True,),
            ("1",),
        )

        for repeats in invalid:
            with self.subTest(repeats=repeats):
                with self.assertRaises(ValueError):
                    run_benchmark(
                        repeats=repeats,
                        trials=1,
                    )

    def test_invalid_trials_and_windows_are_rejected(self):
        for trials in (0, -1, True, 1.5):
            with self.subTest(trials=trials):
                with self.assertRaises(ValueError):
                    run_benchmark(
                        repeats=(1,),
                        trials=trials,
                    )

        for window in (-1, float("nan"), float("inf")):
            with self.subTest(window=window):
                with self.assertRaises(ValueError):
                    run_benchmark(
                        repeats=(1,),
                        trials=1,
                        window_seconds=window,
                    )

    def test_archived_evidence_is_unchanged(self):
        folder = ROOT / "docs/evidence/v0.9"

        def hashes():
            return {
                path.name: hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
                for path in folder.iterdir()
                if path.is_file()
            }

        before = hashes()
        self.assertEqual(len(before), 5)

        run_benchmark(
            repeats=(1,),
            trials=1,
        )

        self.assertEqual(hashes(), before)


if __name__ == "__main__":
    unittest.main()
