"""Tests for V0.8 synthetic association evaluation.

Labels describe simulated activity relationships, not attacks.
Unlabeled predictions and processing errors must not be scored
as true negatives or guessed ground truth.
"""

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from generate_three_source_v08 import generate_dataset
from evaluate_three_source_v08 import evaluate_dataset


class TestThreeSourceEvaluationV08(unittest.TestCase):

    def setUp(self):
        self.dataset = generate_dataset(
            repeats=1, seed=20261011
        )

    def test_confusion_matrix(self):
        result = evaluate_dataset(self.dataset)

        self.assertEqual(
            result["counts"],
            {"tp": 3, "fp": 1, "tn": 2, "fn": 0},
        )
        self.assertEqual(result["candidate_pair_count"], 4)

    def test_metrics_and_research_scope(self):
        result = evaluate_dataset(self.dataset)
        metrics = result["metrics"]

        self.assertAlmostEqual(metrics["precision"], 0.75)
        self.assertAlmostEqual(metrics["recall"], 1.0)
        self.assertAlmostEqual(metrics["f1"], 6 / 7)

        self.assertEqual(result["event_count"], 12)
        self.assertEqual(result["label_count"], 6)
        self.assertEqual(result["window_seconds"], 120)
        self.assertEqual(
            result["evaluation_scope"],
            "predefined_synthetic_activity_relationship",
        )
        self.assertIs(result["production_accuracy_claim"], False)

    def test_each_case_has_expected_classification(self):
        result = evaluate_dataset(self.dataset)

        expected = {
            "P01_windows_ipv4": "TP",
            "P02_linux_ipv4": "TP",
            "P03_linux_ipv6": "TP",
            "N01_nat_collision": "FP",
            "N02_reversed_direction": "TN",
            "N03_wrong_host_mapping": "TN",
        }

        actual = {
            case["scenario"]: case["classification"]
            for case in result["cases"]
        }

        self.assertEqual(actual, expected)
        self.assertEqual(len(result["cases"]), 6)

    def test_short_time_window_causes_missed_pairs(self):
        result = evaluate_dataset(
            self.dataset, window_seconds=44
        )

        self.assertEqual(
            result["counts"],
            {"tp": 0, "fp": 0, "tn": 3, "fn": 3},
        )
        self.assertEqual(result["candidate_pair_count"], 0)
        self.assertEqual(result["metrics"]["precision"], 0.0)
        self.assertEqual(result["metrics"]["recall"], 0.0)
        self.assertEqual(result["metrics"]["f1"], 0.0)

    def test_repeated_dataset_scales_counts(self):
        data = generate_dataset(
            repeats=2, seed=20261011
        )
        result = evaluate_dataset(data)

        self.assertEqual(result["event_count"], 24)
        self.assertEqual(result["label_count"], 12)
        self.assertEqual(result["candidate_pair_count"], 8)
        self.assertEqual(
            result["counts"],
            {"tp": 6, "fp": 2, "tn": 4, "fn": 0},
        )

    def test_input_order_does_not_change_results(self):
        baseline = evaluate_dataset(self.dataset)

        shuffled = copy.deepcopy(self.dataset)
        shuffled["events"].reverse()
        shuffled["labels"].reverse()
        shuffled["host_mappings"].reverse()

        self.assertEqual(evaluate_dataset(shuffled), baseline)

    def test_unlabeled_prediction_is_processing_error(self):
        data = copy.deepcopy(self.dataset)

        data["labels"] = [
            label for label in data["labels"]
            if label["scenario"] != "N01_nat_collision"
        ]

        with self.assertRaises(ValueError):
            evaluate_dataset(data)

    def test_duplicate_and_invalid_labels_rejected(self):
        duplicate = copy.deepcopy(self.dataset)
        duplicate["labels"].append(
            copy.deepcopy(duplicate["labels"][0])
        )

        with self.assertRaises(ValueError):
            evaluate_dataset(duplicate)

        invalid = copy.deepcopy(self.dataset)
        invalid["labels"][0]["related"] = "true"

        with self.assertRaises(ValueError):
            evaluate_dataset(invalid)

    def test_unknown_label_event_rejected(self):
        data = copy.deepcopy(self.dataset)
        data["labels"][0]["event_ids"][0] = "UNKNOWN-EVENT"

        with self.assertRaises(ValueError):
            evaluate_dataset(data)

    def test_invalid_inputs_are_not_scored_as_tn(self):
        malformed_event = copy.deepcopy(self.dataset)
        malformed_event["events"][0]["event_id"] = None

        with self.assertRaises(ValueError):
            evaluate_dataset(malformed_event)

        malformed_mapping = copy.deepcopy(self.dataset)
        malformed_mapping["host_mappings"][0]["ip"] = "invalid-ip"

        with self.assertRaises(ValueError):
            evaluate_dataset(malformed_mapping)

        for value in (-1, True, None, float("nan")):
            with self.subTest(window=value):
                with self.assertRaises(ValueError):
                    evaluate_dataset(
                        self.dataset, window_seconds=value
                    )

    def test_evaluation_does_not_mutate_dataset(self):
        original = copy.deepcopy(self.dataset)

        evaluate_dataset(self.dataset)

        self.assertEqual(self.dataset, original)


if __name__ == "__main__":
    unittest.main()
