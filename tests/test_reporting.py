"""Integration tests for explained security detection reports."""

import copy
import sys
import unittest
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from generate_dataset import generate
from log_analyzer.correlation import correlate_events
from log_analyzer.detection import detect
from log_analyzer.reporting import build_explained_report


PROTECTED = "10.10.20.0/24"
UNTRUSTED = "10.10.30.0/24"


class TestExplainedReporting(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        events, labels = generate(
            repeats=1,
            seed=20261009,
        )

        grouped = defaultdict(list)

        for event in events:
            grouped[event["case_id"]].append(event)

        cls.scenarios = {}

        for label in labels:
            case_events = grouped[label["case_id"]]

            correlation = correlate_events(case_events)

            detection = detect(
                correlation,
                PROTECTED,
                UNTRUSTED,
            )

            cls.scenarios[label["scenario_id"]] = (
                correlation,
                detection,
            )

    def build(self, scenario):
        correlation, detection = self.scenarios[scenario]

        return build_explained_report(
            correlation,
            detection,
        )

    def test_positive_cases_are_enriched(self):
        for scenario in ("P01", "P02", "P03"):
            with self.subTest(scenario=scenario):
                report = self.build(scenario)

                self.assertEqual(
                    report["summary"]["findings"], 1
                )

                self.assertEqual(
                    report["summary"]["unalerted_groups"], 0
                )

                finding = report[
                    "detection_report"
                ]["findings"][0]

                assessment = finding[
                    "evidence_assessment"
                ]

                self.assertEqual(
                    assessment["evidence_level"],
                    "corroborated",
                )

                self.assertFalse(
                    assessment["malicious_intent_determined"]
                )

    def test_corrob_evidence_outside_policy(self):
        for scenario in ("N02", "N03"):
            with self.subTest(scenario=scenario):
                report = self.build(scenario)

                self.assertEqual(
                    report["summary"]["findings"], 0
                )

                self.assertEqual(
                    report["summary"]["unalerted_groups"], 1
                )

                assessment = report[
                    "unalerted_assessments"
                ][0]

                self.assertEqual(
                    assessment["evidence_level"],
                    "corroborated",
                )

    def test_uid_mismatch_remains_separate(self):
        report = self.build("N05")

        self.assertEqual(
            report["summary"]["findings"], 0
        )

        self.assertEqual(
            report["summary"]["assessed_groups"], 2
        )

        self.assertEqual(
            report["summary"]["unalerted_groups"], 2
        )

        self.assertTrue(
            all(
                assessment["evidence_level"] == "partial"
                for assessment in report[
                    "unalerted_assessments"
                ]
            )
        )

    def test_endpoint_conflict(self):
        report = self.build("N06")

        assessment = report[
            "unalerted_assessments"
        ][0]

        self.assertEqual(
            assessment["evidence_level"],
            "conflicting",
        )

        self.assertIn(
            "endpoint_conflict",
            assessment["reason_codes"],
        )

    def test_ntlm_without_connection(self):
        report = self.build("N04")

        self.assertEqual(
            report["summary"]["findings"], 0
        )

        assessment = report[
            "unalerted_assessments"
        ][0]

        self.assertEqual(
            assessment["evidence_level"],
            "partial",
        )

        self.assertIn(
            "missing_connection",
            assessment["reason_codes"],
        )

    def test_original_reports_unchanged(self):
        correlation, detection = self.scenarios["P02"]

        original_correlation = copy.deepcopy(
            correlation
        )

        original_detection = copy.deepcopy(
            detection
        )

        build_explained_report(
            correlation,
            detection,
        )

        self.assertEqual(
            correlation,
            original_correlation,
        )

        self.assertEqual(
            detection,
            original_detection,
        )

    def test_unknown_finding_uid_rejected(self):
        correlation, detection = self.scenarios["P02"]

        modified = copy.deepcopy(detection)

        modified["findings"][0]["uid"] = "UNKNOWN-UID"

        with self.assertRaises(ValueError):
            build_explained_report(
                correlation,
                modified,
            )

    def test_duplicate_correlation_uid_rejected(self):
        correlation, detection = self.scenarios["P02"]

        modified = copy.deepcopy(correlation)

        modified["chains"].append(
            copy.deepcopy(modified["chains"][0])
        )

        with self.assertRaises(ValueError):
            build_explained_report(
                modified,
                detection,
            )

    def test_empty_reports(self):
        report = build_explained_report(
            {"chains": []},
            {"findings": []},
        )

        self.assertEqual(
            report["summary"]["findings"], 0
        )

        self.assertEqual(
            report["summary"]["assessed_groups"], 0
        )

        self.assertEqual(
            report["summary"]["unalerted_groups"], 0
        )

    def test_invalid_inputs_rejected(self):
        with self.assertRaises(ValueError):
            build_explained_report(
                None,
                {"findings": []},
            )

        with self.assertRaises(ValueError):
            build_explained_report(
                {"chains": []},
                None,
            )

        with self.assertRaises(ValueError):
            build_explained_report(
                {"chains": []},
                {"findings": None},
            )


if __name__ == "__main__":
    unittest.main()