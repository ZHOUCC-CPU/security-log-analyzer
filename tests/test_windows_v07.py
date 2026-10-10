
"""Unit tests for the V0.7 Windows Security Event adapter."""

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from log_analyzer.schema_v07 import validate_event
from log_analyzer.windows_v07 import normalize_windows_event


class TestWindowsV07(unittest.TestCase):

    def setUp(self):
        self.raw = {
            "EventID": 4625,
            "TimeCreated": "2026-10-10T08:00:00Z",
            "Computer": "LAB-WIN-01",
            "Channel": "Security",
            "EventRecordID": 42,
            "EventData": {
                "TargetUserName": "synthetic_user",
                "TargetDomainName": "LAB",
                "IpAddress": "192.0.2.10",
                "IpPort": "53122",
                "LogonType": "3",
            },
        }

    def normalize(self, raw=None):
        if raw is None:
            raw = self.raw

        return normalize_windows_event(
            raw,
            filename="synthetic-windows.jsonl",
            line_number=1,
        )

    def test_login_failure(self):
        event = self.normalize()

        self.assertEqual(
            event["event_type"],
            "windows.login_failure",
        )
        self.assertEqual(event["outcome"], "failure")
        self.assertEqual(event["source"]["ip"], "192.0.2.10")
        self.assertEqual(event["source"]["port"], 53122)
        self.assertEqual(event["actor"]["name"], "synthetic_user")
        self.assertTrue(validate_event(event)["valid"])

    def test_login_success(self):
        raw = copy.deepcopy(self.raw)
        raw["EventID"] = 4624

        event = self.normalize(raw)

        self.assertEqual(
            event["event_type"],
            "windows.login_success",
        )
        self.assertEqual(event["outcome"], "success")
        self.assertTrue(validate_event(event)["valid"])

    def test_special_privileges(self):
        raw = copy.deepcopy(self.raw)
        raw["EventID"] = 4672
        raw["EventData"] = {
            "SubjectUserName": "synthetic_admin",
            "SubjectDomainName": "LAB",
            "SubjectLogonId": "0x1234",
        }

        event = self.normalize(raw)

        self.assertEqual(
            event["event_type"],
            "windows.special_privileges",
        )
        self.assertEqual(event["actor"]["name"], "synthetic_admin")
        self.assertIsNone(event["outcome"])
        self.assertIsNone(event["source"])
        self.assertTrue(validate_event(event)["valid"])

    def test_missing_ip_does_not_invent_endpoint(self):
        raw = copy.deepcopy(self.raw)
        raw["EventData"]["IpAddress"] = "-"
        raw["EventData"]["IpPort"] = "-"

        event = self.normalize(raw)

        self.assertIsNone(event["source"])
        self.assertTrue(validate_event(event)["valid"])

    def test_timezone_offset_converted_to_utc(self):
        raw = copy.deepcopy(self.raw)
        raw["TimeCreated"] = "2026-10-10T16:00:00+08:00"

        event = self.normalize(raw)

        self.assertEqual(
            event["timestamp_utc"],
            "2026-10-10T08:00:00Z",
        )

    def test_naive_timestamp_rejected(self):
        raw = copy.deepcopy(self.raw)
        raw["TimeCreated"] = "2026-10-10T08:00:00"

        with self.assertRaises(ValueError):
            self.normalize(raw)

    def test_invalid_ip_rejected(self):
        raw = copy.deepcopy(self.raw)
        raw["EventData"]["IpAddress"] = "999.999.999.999"

        with self.assertRaises(ValueError):
            self.normalize(raw)

    def test_unsupported_event_id_rejected(self):
        raw = copy.deepcopy(self.raw)
        raw["EventID"] = 9999

        with self.assertRaises(ValueError):
            self.normalize(raw)

    def test_provenance_and_identity(self):
        event = self.normalize()

        self.assertEqual(
            event["event_id"],
            "windows:LAB-WIN-01:Security:42",
        )
        self.assertEqual(
            event["provenance"],
            {
                "filename": "synthetic-windows.jsonl",
                "line_number": 1,
            },
        )
        self.assertEqual(event["schema_version"], "0.7.0")

    def test_input_not_modified(self):
        original = copy.deepcopy(self.raw)

        self.normalize()

        self.assertEqual(self.raw, original)


if __name__ == "__main__":
    unittest.main()
