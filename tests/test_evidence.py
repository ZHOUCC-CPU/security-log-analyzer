"""Tests for evidence completeness assessment in V0.5."""

import sys
import unittest
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from generate_dataset import generate
from log_analyzer.correlation import correlate_events
from log_analyzer.evidence import assess_chain, assess_correlation


EXPECTED_LEVELS = {
    "P01": ["corroborated"],
    "P02": ["corroborated"],
    "P03": ["corroborated"],
    "N01": ["partial"],
    "N02": ["corroborated"],
    "N03": ["corroborated"],
    "N04": ["partial"],
    "N05": ["partial", "partial"],
    "N06": ["conflicting"],
    "N07": ["conflicting"],
    "N08": ["conflicting"],
}


class TestEvidenceAssessment(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        events, labels = generate(
            repeats=1,
            seed=20261009,
        )

        events_by_case = defaultdict(list)

        for event in events:
            events_by_case[event["case_id"]].append(event)

        cls.reports = {}

        for label in labels:
            scenario = label["scenario_id"]
            case_events = events_by_case[label["case_id"]]

            correlation = correlate_events(case_events)
            cls.reports[scenario] = assess_correlation(correlation)

    def test_all_scenario_levels(self):
        for scenario, expected in EXPECTED_LEVELS.items():
            with self.subTest(scenario=scenario):
                report = self.reports[scenario]

                actual = sorted(
                    item["evidence_level"]
                    for item in report["assessments"]
                )

                self.assertEqual(actual, sorted(expected))

    def test_all_scenario_summaries(self):
        for scenario, report in self.reports.items():
            with self.subTest(scenario=scenario):
                summary = report["summary"]

                total = sum(
                    summary[level]
                    for level in (
                        "corroborated",
                        "partial",
                        "conflicting",
                        "no_relevant_evidence",
                    )
                )

                self.assertEqual(
                    total,
                    summary["total_groups"],
                )

    def test_notice_is_optional(self):
        with_notice = self.reports["P01"]["assessments"][0]
        without_notice = self.reports["P02"]["assessments"][0]

        self.assertEqual(
            with_notice["evidence_level"],
            "corroborated",
        )

        self.assertEqual(
            without_notice["evidence_level"],
            "corroborated",
        )

        self.assertIn(
            "notice_present",
            with_notice["reason_codes"],
        )

        self.assertIn(
            "notice_absent",
            without_notice["reason_codes"],
        )

    def test_trust_boundary_is_separate(self):
        for scenario in ("N02", "N03"):
            with self.subTest(scenario=scenario):
                assessment = (
                    self.reports[scenario]["assessments"][0]
                )

                self.assertEqual(
                    assessment["evidence_level"],
                    "corroborated",
                )

                self.assertFalse(
                    assessment["malicious_intent_determined"]
                )

    def test_uid_mismatch_not_merged(self):
        report = self.reports["N05"]

        self.assertEqual(
            report["summary"]["total_groups"],
            2,
        )

        self.assertEqual(
            report["summary"]["partial"],
            2,
        )

        uids = [
            item["uid"]
            for item in report["assessments"]
        ]

        self.assertEqual(len(set(uids)), 2)

    def test_provenance_preserved(self):
        assessment = (
            self.reports["P02"]["assessments"][0]
        )

        self.assertEqual(
            len(assessment["evidence_refs"]),
            2,
        )

        for ref in assessment["evidence_refs"]:
            self.assertTrue(ref["event_id"])
            self.assertTrue(ref["filename"])

            self.assertIsInstance(
                ref["line_number"],
                int,
            )

        self.assertFalse(
            assessment["malicious_intent_determined"]
        )

    def test_empty_report(self):
        result = assess_correlation({"chains": []})

        self.assertEqual(
            result["summary"]["total_groups"],
            0,
        )

        self.assertEqual(
            result["assessments"],
            [],
        )

    def test_invalid_inputs(self):
        with self.assertRaises(ValueError):
            assess_correlation(None)

        with self.assertRaises(ValueError):
            assess_correlation({"chains": None})

        with self.assertRaises(ValueError):
            assess_chain({"uid": "TEST"})

        with self.assertRaises(ValueError):
            assess_chain(None)


if __name__ == "__main__":
    unittest.main()