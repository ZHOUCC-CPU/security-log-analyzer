"""Regression tests for synthetic telemetry robustness experiments."""

import copy
import sys
import unittest
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from generate_dataset import generate
from robustness_v04 import perturb, evaluate, CONDITIONS


EXPECTED = {
    "original": (1, 1, 1),
    "missing_connection": (0, 1, 0),
    "missing_ntlm": (1, 0, 0),
    "missing_notice": (1, 1, 1),
    "uid_mismatch": (1, 1, 0),
    "timestamp_skew": (1, 1, 0),
    "reversed_input": (1, 1, 1),
}


class TestRobustness(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        events, labels = generate(repeats=1, seed=20261009)

        grouped = defaultdict(list)
        for event in events:
            grouped[event["case_id"]].append(event)

        cls.positive_cases = [
            (label, grouped[label["case_id"]])
            for label in labels
            if label["behavior_label"] == 1
        ]

        assert len(cls.positive_cases) == 3

    def check_condition(self, condition):
        expected = EXPECTED[condition]

        for label, events in self.positive_cases:
            with self.subTest(
                condition=condition,
                scenario=label["scenario_id"],
            ):
                modified = perturb(events, condition)
                result = evaluate(modified)

                actual = (
                    result["baseline_a"],
                    result["baseline_b"],
                    result["r001"],
                )

                self.assertEqual(actual, expected)

    def test_original(self):
        self.check_condition("original")

    def test_missing_connection(self):
        self.check_condition("missing_connection")

    def test_missing_ntlm(self):
        self.check_condition("missing_ntlm")

    def test_missing_notice(self):
        self.check_condition("missing_notice")

    def test_uid_mismatch(self):
        self.check_condition("uid_mismatch")

    def test_timestamp_skew(self):
        self.check_condition("timestamp_skew")

    def test_reversed_input(self):
        self.check_condition("reversed_input")

    def test_input_data_unchanged(self):
        for _, events in self.positive_cases:
            original = copy.deepcopy(events)

            for condition in CONDITIONS:
                perturb(events, condition)
                self.assertEqual(events, original)

    def test_authorized_behavior(self):
        authorized = [
            (label, events)
            for label, events in self.positive_cases
            if label["intent_annotation"] == "authorized"
        ]

        self.assertEqual(len(authorized), 1)

        label, events = authorized[0]
        self.assertEqual(label["behavior_label"], 1)
        self.assertEqual(evaluate(events)["r001"], 1)


if __name__ == "__main__":
    unittest.main()