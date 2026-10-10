"""Regression tests for V0.6 normalized-event quality assessment."""

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from log_analyzer.quality import assess_event_quality


class TestEventQuality(unittest.TestCase):

    def setUp(self):
        self.event = {
            "event_id": "EVT-001",
            "event_type": "zeek.conn",
            "uid": "UID-001",
            "timestamp_utc": "2026-10-10T00:00:00Z",
            "source": {
                "ip": "10.10.20.10",
                "port": 50123,
            },
            "destination": {
                "ip": "10.10.30.10",
                "port": 445,
            },
        }

    def audit(self, events):
        return assess_event_quality(events)

    def test_clean_event(self):
        result = self.audit([self.event])

        self.assertEqual(result["summary"]["total_records"], 1)
        self.assertEqual(result["summary"]["clean_records"], 1)
        self.assertEqual(result["summary"]["records_with_issues"], 0)

    def test_duplicate_event_id(self):
        result = self.audit([
            self.event,
            copy.deepcopy(self.event),
        ])

        self.assertEqual(
            result["issue_counts"]["duplicate_event_id"], 1
        )
        self.assertEqual(
            result["sample_issues"][0]["record_index"], 2
        )

    def test_missing_uid(self):
        event = copy.deepcopy(self.event)
        event["uid"] = None

        result = self.audit([event])

        self.assertEqual(
            result["issue_counts"]["missing_uid"], 1
        )

    def test_invalid_timestamp(self):
        event = copy.deepcopy(self.event)
        event["timestamp_utc"] = "invalid-time"

        result = self.audit([event])

        self.assertEqual(
            result["issue_counts"]["invalid_timestamp"], 1
        )

    def test_invalid_source_ip(self):
        event = copy.deepcopy(self.event)
        event["source"]["ip"] = "999.999.999.999"

        result = self.audit([event])

        self.assertEqual(
            result["issue_counts"]["invalid_source_ip"], 1
        )

    def test_missing_destination_ip(self):
        event = copy.deepcopy(self.event)
        event["destination"]["ip"] = None

        result = self.audit([event])

        self.assertEqual(
            result["issue_counts"]["missing_destination_ip"], 1
        )

    def test_invalid_port(self):
        event = copy.deepcopy(self.event)
        event["destination"]["port"] = 70000

        result = self.audit([event])

        self.assertEqual(
            result["issue_counts"]["invalid_destination_port"], 1
        )

    def test_unsupported_event_type(self):
        event = copy.deepcopy(self.event)
        event["event_type"] = "unknown.event"

        result = self.audit([event])

        self.assertEqual(
            result["issue_counts"]["unsupported_event_type"], 1
        )

    def test_invalid_record(self):
        result = self.audit([None])

        self.assertEqual(
            result["issue_counts"]["invalid_record"], 1
        )

    def test_multiple_issues_and_sample_limit(self):
        first = copy.deepcopy(self.event)
        first["uid"] = None
        first["timestamp_utc"] = "bad-time"

        second = copy.deepcopy(self.event)
        second["event_id"] = "EVT-002"
        second["destination"]["ip"] = "invalid-ip"

        result = assess_event_quality(
            [first, second],
            sample_limit=1,
        )

        self.assertEqual(
            result["summary"]["records_with_issues"], 2
        )
        self.assertEqual(
            result["summary"]["issue_occurrences"], 3
        )
        self.assertEqual(len(result["sample_issues"]), 1)

    def test_does_not_mutate_input(self):
        events = [copy.deepcopy(self.event)]
        original = copy.deepcopy(events)

        self.audit(events)

        self.assertEqual(events, original)

    def test_invalid_sample_limit(self):
        for value in (-1, True, 1.5):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    assess_event_quality(
                        [self.event],
                        sample_limit=value,
                    )

    def test_empty_input(self):
        result = self.audit([])

        self.assertEqual(
            result["summary"]["total_records"], 0
        )
        self.assertEqual(
            result["summary"]["issue_occurrences"], 0
        )


if __name__ == "__main__":
    unittest.main()