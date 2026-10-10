"""Regression tests for V0.6 telemetry quality impact experiments."""

import copy
import sys
import unittest
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from generate_dataset import generate
from quality_impact_v06 import (
    CONDITIONS,
    inject_fault,
    run_experiment,
)


class TestQualityImpactV06(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.report = run_experiment(
            ROOT / "datasets/synthetic/v0.4"
        )

        events, labels = generate(
            repeats=1,
            seed=20261009,
        )

        grouped = defaultdict(list)

        for event in events:
            grouped[event["case_id"]].append(event)

        positive = next(
            label for label in labels
            if label["behavior_label"] == 1
        )

        cls.sample_events = grouped[positive["case_id"]]

    def summary(self, condition):
        return self.report["summary"][condition]

    def test_experiment_size(self):
        self.assertEqual(
            self.report["original_positive_cases"], 30
        )
        self.assertEqual(
            self.report["total_case_condition_runs"], 240
        )
        self.assertEqual(
            len(self.report["case_results"]), 240
        )

        counts = Counter(
            row["condition"]
            for row in self.report["case_results"]
        )

        for condition in CONDITIONS:
            with self.subTest(condition=condition):
                self.assertEqual(counts[condition], 30)

    def test_outcome_accounting(self):
        for condition in CONDITIONS:
            with self.subTest(condition=condition):
                row = self.summary(condition)

                total = (
                    row["r001_alerts"]
                    + row["no_r001_alert"]
                    + row["processing_errors"]
                )

                self.assertEqual(total, row["cases"])

    def test_original(self):
        row = self.summary("original")

        self.assertEqual(row["r001_alerts"], 30)
        self.assertEqual(row["quality_flagged_cases"], 0)
        self.assertEqual(row["processing_errors"], 0)

    def test_duplicate_ntlm(self):
        row = self.summary("duplicate_ntlm")

        self.assertEqual(row["r001_alerts"], 30)
        self.assertEqual(row["quality_flagged_cases"], 30)
        self.assertEqual(
            row["issue_counts"]["duplicate_event_id"], 30
        )

    def test_missing_ntlm_uid(self):
        row = self.summary("missing_ntlm_uid")

        self.assertEqual(row["r001_alerts"], 0)
        self.assertEqual(row["no_r001_alert"], 30)
        self.assertEqual(
            row["issue_counts"]["missing_uid"], 30
        )

    def test_missing_ntlm_source_ip(self):
        row = self.summary("missing_ntlm_source_ip")

        # Strict endpoint integrity prevents alert promotion
        # when required NTLM source evidence is missing.
        self.assertEqual(row["r001_alerts"], 0)
        self.assertEqual(row["no_r001_alert"], 30)
        self.assertEqual(row["processing_errors"], 0)
        self.assertEqual(row["quality_flagged_cases"], 30)
        self.assertEqual(
            row["issue_counts"]["missing_source_ip"], 30
        )

    def test_invalid_ntlm_source_ip(self):
        row = self.summary("invalid_ntlm_source_ip")

        self.assertEqual(row["r001_alerts"], 0)
        self.assertEqual(row["no_r001_alert"], 30)
        self.assertEqual(
            row["issue_counts"]["invalid_source_ip"], 30
        )

    def test_invalid_timestamp_is_error(self):
        row = self.summary("invalid_ntlm_timestamp")

        self.assertEqual(row["processing_errors"], 30)
        self.assertEqual(row["r001_alerts"], 0)
        self.assertEqual(row["no_r001_alert"], 0)
        self.assertEqual(
            row["issue_counts"]["invalid_timestamp"], 30
        )
        self.assertIsNone(
            row["alert_fraction_of_processed_cases"]
        )

    def test_dropped_ntlm(self):
        row = self.summary("drop_ntlm")

        self.assertEqual(row["r001_alerts"], 0)
        self.assertEqual(row["no_r001_alert"], 30)
        self.assertEqual(row["quality_flagged_cases"], 0)

    def test_timestamp_skew(self):
        row = self.summary("timestamp_skew_back_60s")

        self.assertEqual(row["r001_alerts"], 0)
        self.assertEqual(row["no_r001_alert"], 30)
        self.assertEqual(row["quality_flagged_cases"], 0)

    def test_fault_injection_preserves_original(self):
        original = copy.deepcopy(self.sample_events)

        for condition in CONDITIONS:
            with self.subTest(condition=condition):
                inject_fault(self.sample_events, condition)

                self.assertEqual(
                    self.sample_events,
                    original,
                )

    def test_unknown_fault_rejected(self):
        with self.assertRaises(ValueError):
            inject_fault(
                self.sample_events,
                "unknown_condition",
            )


if __name__ == "__main__":
    unittest.main()