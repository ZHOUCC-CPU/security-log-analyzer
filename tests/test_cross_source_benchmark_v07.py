
"""Tests for the V0.7 cross-source benchmark evaluator."""

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from generate_cross_source_v07 import generate_dataset
from evaluate_cross_source_v07 import evaluate_dataset


class TestCrossSourceBenchmarkV07(unittest.TestCase):

    def setUp(self):
        self.dataset = generate_dataset(
            repeats=1,
            seed=20261010,
        )

    def evaluate(self, dataset=None, **kwargs):
        return evaluate_dataset(
            self.dataset if dataset is None else dataset,
            **kwargs,
        )

    def classification(self, result, scenario):
        matches = [
            case for case in result["cases"]
            if case["scenario"] == scenario
        ]
        self.assertEqual(len(matches), 1)
        return matches[0]["classification"]

    def test_confusion_matrix(self):
        result = self.evaluate()

        self.assertEqual(
            result["counts"],
            {
                "tp": 3,
                "fp": 2,
                "tn": 6,
                "fn": 1,
            },
        )

    def test_precision_recall_f1(self):
        metrics = self.evaluate()["metrics"]

        self.assertAlmostEqual(
            metrics["precision"], 0.60
        )
        self.assertAlmostEqual(
            metrics["recall"], 0.75
        )
        self.assertAlmostEqual(
            metrics["f1"], 2 / 3
        )

    def test_false_positive_scenarios(self):
        result = self.evaluate()

        self.assertEqual(
            self.classification(
                result, "N04_nat_collision"
            ),
            "FP",
        )

        self.assertEqual(
            self.classification(
                result, "N05_shared_account_collision"
            ),
            "FP",
        )

    def test_delayed_positive_is_false_negative(self):
        result = self.evaluate()

        self.assertEqual(
            self.classification(
                result, "P04_delayed_related_activity"
            ),
            "FN",
        )

    def test_time_boundary_is_true_positive(self):
        result = self.evaluate()

        self.assertEqual(
            self.classification(
                result, "P03_time_boundary"
            ),
            "TP",
        )

    def test_multicast_is_true_negative(self):
        result = self.evaluate()

        self.assertEqual(
            self.classification(
                result, "N08_multicast_source"
            ),
            "TN",
        )

    def test_evaluation_inventory(self):
        result = self.evaluate()

        self.assertEqual(result["label_count"], 12)
        self.assertEqual(result["candidate_pair_count"], 5)
        self.assertEqual(len(result["cases"]), 12)

    def test_repeated_dataset_scales_counts(self):
        dataset = generate_dataset(
            repeats=2,
            seed=20261010,
        )

        result = self.evaluate(dataset)

        self.assertEqual(
            result["counts"],
            {
                "tp": 6,
                "fp": 4,
                "tn": 12,
                "fn": 2,
            },
        )

        self.assertEqual(result["label_count"], 24)

    def test_order_independent(self):
        first = self.evaluate()

        reversed_dataset = copy.deepcopy(self.dataset)

        reversed_dataset["events"].reverse()
        reversed_dataset["labels"].reverse()

        second = self.evaluate(reversed_dataset)

        self.assertEqual(first, second)

    def test_does_not_modify_dataset(self):
        original = copy.deepcopy(self.dataset)

        self.evaluate()

        self.assertEqual(self.dataset, original)

    def test_unknown_event_reference_rejected(self):
        dataset = copy.deepcopy(self.dataset)

        dataset["labels"][0]["event_ids"][0] = (
            "NONEXISTENT-EVENT"
        )

        with self.assertRaises(ValueError):
            self.evaluate(dataset)

    def test_duplicate_pair_label_rejected(self):
        dataset = copy.deepcopy(self.dataset)

        duplicate = copy.deepcopy(
            dataset["labels"][0]
        )
        duplicate["case_id"] = "DUPLICATE-CASE"

        dataset["labels"].append(duplicate)

        with self.assertRaises(ValueError):
            self.evaluate(dataset)

    def test_unlabeled_prediction_rejected(self):
        dataset = copy.deepcopy(self.dataset)

        # Add a new synthetic Windows event matching
        # an existing Linux event, but with no ground
        # truth label for this additional pair.
        extra = copy.deepcopy(dataset["events"][0])
        extra["event_id"] = "EXTRA-WINDOWS-001"

        dataset["events"].append(extra)

        # Without a predefined relationship label,
        # the new association cannot be honestly
        # classified as TP or FP.
        with self.assertRaises(ValueError):
            self.evaluate(dataset)

    def test_invalid_window_rejected(self):
        for value in (-1, True, float("nan"), "120"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    self.evaluate(
                        window_seconds=value
                    )

    def test_no_production_accuracy_claim(self):
        result = self.evaluate()

        self.assertEqual(
            result["evaluation_scope"],
            "predefined_synthetic_activity_relationship",
        )

        self.assertIs(
            result["production_accuracy_claim"],
            False,
        )


if __name__ == "__main__":
    unittest.main()
