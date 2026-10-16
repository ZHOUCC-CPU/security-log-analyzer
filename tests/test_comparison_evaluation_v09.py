"""TDD tests for the V0.9 three-method evaluation."""

import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from generate_comparison_v09 import generate_expanded_dataset
from evaluate_comparison_v09 import evaluate_comparison


EXPECTED = {
    "time_only": {"tp": 7, "fp": 8, "tn": 0, "fn": 1},
    "ip_time": {"tp": 6, "fp": 6, "tn": 2, "fn": 2},
    "v08_policy": {"tp": 5, "fp": 1, "tn": 7, "fn": 3},
}


class TestComparisonEvaluationV09(unittest.TestCase):

    def setUp(self):
        self.dataset = generate_expanded_dataset(
            repeats=1, seed=20261011
        )

    def test_all_three_confusion_matrices(self):
        result = evaluate_comparison(self.dataset)
        self.assertEqual(result["label_count"], 16)
        self.assertEqual(set(result["methods"]), set(EXPECTED))
        for name, counts in EXPECTED.items():
            with self.subTest(method=name):
                self.assertEqual(
                    result["methods"][name]["counts"], counts
                )

    def test_precision_recall_and_f1(self):
        result = evaluate_comparison(self.dataset)
        expected = {
            "time_only": (7/15, 7/8, 14/23),
            "ip_time": (6/12, 6/8, 12/20),
            "v08_policy": (5/6, 5/8, 10/14),
        }
        for name, scores in expected.items():
            actual = result["methods"][name]["metrics"]
            for key, value in zip(
                ("precision", "recall", "f1"), scores
            ):
                with self.subTest(method=name, metric=key):
                    self.assertAlmostEqual(actual[key], value)

    def test_44_second_window_excludes_all(self):
        result = evaluate_comparison(
            self.dataset, window_seconds=44
        )
        for method in result["methods"].values():
            self.assertEqual(
                method["counts"],
                {"tp": 0, "fp": 0, "tn": 8, "fn": 8},
            )

    def test_121_second_window_is_inclusive(self):
        result = evaluate_comparison(
            self.dataset, window_seconds=121
        )
        expected = {
            "time_only": (8, 8, 0, 0),
            "ip_time": (7, 6, 2, 1),
            "v08_policy": (6, 1, 7, 2),
        }
        for name, values in expected.items():
            counts = result["methods"][name]["counts"]
            self.assertEqual(
                tuple(counts[k] for k in ("tp", "fp", "tn", "fn")),
                values,
            )

    def test_important_case_outcomes(self):
        result = evaluate_comparison(self.dataset)
        expected = {
            "P05_outside_120": ("FN", "FN", "FN"),
            "P07_port_translation": ("TP", "TP", "FN"),
            "P08_missing_zeek_source_ip": ("TP", "FN", "FN"),
            "N01_nat_collision": ("FP", "FP", "FP"),
        }
        names = ("time_only", "ip_time", "v08_policy")
        for scenario, outcomes in expected.items():
            for name, classification in zip(names, outcomes):
                cases = result["methods"][name]["cases"]
                case = next(
                    x for x in cases
                    if x["scenario"] == scenario
                )
                self.assertEqual(
                    case["classification"], classification
                )

    def test_input_is_not_mutated(self):
        before = copy.deepcopy(self.dataset)
        evaluate_comparison(self.dataset)
        self.assertEqual(self.dataset, before)

    def test_results_are_deterministic(self):
        first = evaluate_comparison(self.dataset)
        second = evaluate_comparison(
            generate_expanded_dataset(
                repeats=1, seed=20261011
            )
        )
        self.assertEqual(first, second)

    def test_duplicate_label_is_rejected(self):
        data = copy.deepcopy(self.dataset)
        data["labels"].append(copy.deepcopy(data["labels"][0]))
        with self.assertRaises(ValueError):
            evaluate_comparison(data)

    def test_unlabeled_prediction_is_rejected(self):
        with patch(
            "evaluate_comparison_v09.find_time_only_pairs",
            return_value=[("unknown-zeek", "unknown-host")],
        ):
            with self.assertRaises(ValueError):
                evaluate_comparison(self.dataset)

    def test_duplicate_prediction_is_rejected(self):
        pair = tuple(self.dataset["labels"][0]["event_ids"])
        with patch(
            "evaluate_comparison_v09.find_time_only_pairs",
            return_value=[pair, pair],
        ):
            with self.assertRaises(ValueError):
                evaluate_comparison(self.dataset)


if __name__ == "__main__":
    unittest.main()
