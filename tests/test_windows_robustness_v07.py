
"""Robustness and evidence-integrity tests for Windows V0.7."""

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from log_analyzer.schema_v07 import validate_event
from log_analyzer.windows_v07 import normalize_windows_event


class TestWindowsRobustnessV07(unittest.TestCase):

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
                "TargetLogonId": "0x1234",
            },
        }

    def normalize(self, raw=None, **kwargs):
        if raw is None:
            raw = self.raw

        options = {
            "filename": "synthetic-windows.jsonl",
            "line_number": 1,
        }
        options.update(kwargs)

        return normalize_windows_event(raw, **options)

    def test_ipv6_source_preserved(self):
        raw = copy.deepcopy(self.raw)
        raw["EventData"]["IpAddress"] = "2001:db8::10"

        event = self.normalize(raw)

        self.assertEqual(
            event["source"]["ip"],
            "2001:db8::10",
        )
        self.assertTrue(validate_event(event)["valid"])

    def test_missing_actor_not_fabricated(self):
        raw = copy.deepcopy(self.raw)
        raw["EventData"].pop("TargetUserName")
        raw["EventData"].pop("TargetDomainName")

        event = self.normalize(raw)

        self.assertIsNone(event["actor"])
        self.assertTrue(validate_event(event)["valid"])

    def test_privilege_event_not_login_evidence(self):
        raw = copy.deepcopy(self.raw)
        raw["EventID"] = 4672
        raw["EventData"] = {
            "SubjectUserName": "synthetic_admin",
            "SubjectLogonId": "0x1234",
        }

        event = self.normalize(raw)

        self.assertEqual(
            event["event_type"],
            "windows.special_privileges",
        )
        self.assertIsNone(event["outcome"])
        self.assertIsNone(event["source"])

    def test_missing_event_data_rejected(self):
        raw = copy.deepcopy(self.raw)
        raw.pop("EventData")

        with self.assertRaises(ValueError):
            self.normalize(raw)

    def test_wrong_channel_rejected(self):
        raw = copy.deepcopy(self.raw)
        raw["Channel"] = "System"

        with self.assertRaises(ValueError):
            self.normalize(raw)

    def test_missing_host_rejected(self):
        raw = copy.deepcopy(self.raw)
        raw["Computer"] = ""

        with self.assertRaises(ValueError):
            self.normalize(raw)

    def test_boolean_event_id_rejected(self):
        raw = copy.deepcopy(self.raw)
        raw["EventID"] = True

        with self.assertRaises(ValueError):
            self.normalize(raw)

    def test_invalid_record_id_rejected(self):
        raw = copy.deepcopy(self.raw)
        raw["EventRecordID"] = 0

        with self.assertRaises(ValueError):
            self.normalize(raw)

    def test_port_without_ip_rejected(self):
        raw = copy.deepcopy(self.raw)
        raw["EventData"]["IpAddress"] = "-"
        raw["EventData"]["IpPort"] = "53122"

        with self.assertRaises(ValueError):
            self.normalize(raw)

    def test_invalid_provenance_rejected(self):
        with self.assertRaises(ValueError):
            self.normalize(line_number=0)

    def test_malformed_logon_type_rejected(self):
        raw = copy.deepcopy(self.raw)
        raw["EventData"]["LogonType"] = {
            "unexpected": "nested object"
        }

        with self.assertRaises(ValueError):
            self.normalize(raw)

    def test_malformed_logon_id_rejected(self):
        raw = copy.deepcopy(self.raw)
        raw["EventData"]["TargetLogonId"] = {
            "unexpected": "nested object"
        }

        with self.assertRaises(ValueError):
            self.normalize(raw)


if __name__ == "__main__":
    unittest.main()
