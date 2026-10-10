
"""Windows V0.7 source endpoint semantics tests."""

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from log_analyzer.windows_v07 import normalize_windows_event


class TestWindowsSourceV07(unittest.TestCase):

    def setUp(self):
        self.raw = {
            "EventID": 4624,
            "TimeCreated": "2026-10-10T08:00:00Z",
            "Computer": "LAB-WIN-01",
            "Channel": "Security",
            "EventRecordID": 100,
            "EventData": {
                "TargetUserName": "synthetic_user",
                "TargetDomainName": "LAB",
                "IpAddress": "192.0.2.10",
                "IpPort": "53122",
                "LogonType": "3",
            },
        }

    def normalize(self, raw):
        return normalize_windows_event(
            raw,
            filename="synthetic-source.jsonl",
            line_number=1,
        )

    def test_missing_ip_with_zero_port_string(self):
        raw = copy.deepcopy(self.raw)
        raw["EventData"]["IpAddress"] = "-"
        raw["EventData"]["IpPort"] = "0"

        event = self.normalize(raw)

        self.assertIsNone(event["source"])

    def test_missing_ip_with_zero_port_integer(self):
        raw = copy.deepcopy(self.raw)
        raw["EventData"]["IpAddress"] = "-"
        raw["EventData"]["IpPort"] = 0

        event = self.normalize(raw)

        self.assertIsNone(event["source"])

    def test_missing_ip_and_port(self):
        raw = copy.deepcopy(self.raw)
        raw["EventData"]["IpAddress"] = None
        raw["EventData"]["IpPort"] = None

        event = self.normalize(raw)

        self.assertIsNone(event["source"])

    def test_missing_ip_with_nonzero_port_rejected(self):
        raw = copy.deepcopy(self.raw)
        raw["EventData"]["IpAddress"] = "-"
        raw["EventData"]["IpPort"] = "53122"

        with self.assertRaises(ValueError):
            self.normalize(raw)

    def test_present_ip_with_zero_port_preserved(self):
        raw = copy.deepcopy(self.raw)
        raw["EventData"]["IpPort"] = "0"

        event = self.normalize(raw)

        self.assertEqual(
            event["source"],
            {"ip": "192.0.2.10", "port": 0},
        )

    def test_system_account_preserved(self):
        raw = copy.deepcopy(self.raw)
        raw["EventData"]["TargetUserName"] = "SYSTEM"
        raw["EventData"]["TargetDomainName"] = "NT AUTHORITY"

        event = self.normalize(raw)

        self.assertEqual(event["actor"]["name"], "SYSTEM")
        self.assertEqual(
            event["actor"]["domain"],
            "NT AUTHORITY",
        )


if __name__ == "__main__":
    unittest.main()
