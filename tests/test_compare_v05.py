"""Regression tests for V0.5 comparison against V0.4."""

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from benchmark_v04 import run_benchmark
from compare_v05 import compare


class TestV05Comparison(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dataset = ROOT / "datasets/synthetic/v0.4"
        cls.temp = tempfile.TemporaryDirectory()
        cls.previous = Path(cls.temp.name) / "benchmark.json"

        cls.original = run_benchmark(cls.dataset)

        cls.previous.write_text(
            json.dumps(cls.original, indent=2),
            encoding="utf-8",
        )

        cls.report = compare(cls.dataset, cls.previous)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_detection_compatibility(self):
        self.assertTrue(
            self.report["v04_predictions_preserved"]
        )
        self.assertTrue(
            self.report["v04_finding_data_preserved"]
        )

    def test_expected_counts(self):
        report = self.report

        self.assertEqual(report["cases"], 110)
        self.assertEqual(report["findings"], 30)
        self.assertEqual(report["assessed_groups"], 120)
        self.assertEqual(report["unalerted_groups"], 90)
        self.assertEqual(report["authorized_cases_flagged"], 10)

    def test_evidence_distribution(self):
        self.assertEqual(
            self.report["evidence_levels"],
            {
                "corroborated": 50,
                "partial": 40,
                "conflicting": 30,
                "no_relevant_evidence": 0,
            },
        )

        self.assertEqual(
            self.report["unalerted_evidence_levels"],
            {
                "corroborated": 20,
                "partial": 40,
                "conflicting": 30,
                "no_relevant_evidence": 0,
            },
        )

    def test_scenario_distribution(self):
        expected = {
            "P01": ("corroborated", 10),
            "P02": ("corroborated", 10),
            "P03": ("corroborated", 10),
            "N01": ("partial", 10),
            "N02": ("corroborated", 10),
            "N03": ("corroborated", 10),
            "N04": ("partial", 10),
            "N05": ("partial", 20),
            "N06": ("conflicting", 10),
            "N07": ("conflicting", 10),
            "N08": ("conflicting", 10),
        }

        for scenario, (level, count) in expected.items():
            with self.subTest(scenario=scenario):
                actual = self.report[
                    "scenario_levels"
                ][scenario][level]

                self.assertEqual(actual, count)

    def test_modified_predictions_rejected(self):
        modified = copy.deepcopy(self.original)

        case = modified["case_results"][0]
        predictions = case["predictions"]

        predictions["r001_correlated"] = (
            1 - predictions["r001_correlated"]
        )

        path = Path(self.temp.name) / "modified.json"
        path.write_text(
            json.dumps(modified),
            encoding="utf-8",
        )

        with self.assertRaises(ValueError):
            compare(self.dataset, path)

    def test_modified_dataset_hash_rejected(self):
        modified = copy.deepcopy(self.original)

        modified["dataset_manifest"]["sha256"][
            "events.jsonl"
        ] = "0" * 64

        path = Path(self.temp.name) / "wrong-hash.json"
        path.write_text(
            json.dumps(modified),
            encoding="utf-8",
        )

        with self.assertRaises(ValueError):
            compare(self.dataset, path)


if __name__ == "__main__":
    unittest.main()