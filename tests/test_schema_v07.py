
"""Tests for the V0.7 unified security-event schema."""

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from log_analyzer.schema_v07 import validate_event


class TestSchemaV07(unittest.TestCase):

    def setUp(self):
        self.event = {
            "schema_version": "0.7.0",
            "event_id": "SYN-WIN-001",
            "timestamp_utc": "2026-10-10T08:00:00Z",
            "source_type": "windows",
            "event_type": "windows.login_failure",
            "uid": None,
            "source": {
                "ip": "192.0.2.10",
                "port": 51234,
            },
            "destination": None,
            "host": {"name": "LAB-WIN-01"},
            "actor": {"name": "synthetic_user"},
            "outcome": "failure",
            "details": {"windows_event_id": 4625},
            "provenance": {
                "filename": "synthetic-windows.jsonl",
                "line_number": 1,
            },
        }

    def test_valid_windows_event(self):
        result = validate_event(self.event)
        self.assertEqual(
            result,
            {"valid": True, "issues": []},
        )

    def test_valid_linux_event(self):
        event = copy.deepcopy(self.event)
        event["source_type"] = "linux"
        event["event_type"] = "linux.ssh_failure"

        self.assertTrue(validate_event(event)["valid"])

    def test_valid_zeek_v07_event(self):
        event = copy.deepcopy(self.event)
        event["source_type"] = "zeek"
        event["event_type"] = "zeek.ntlm"
        event["uid"] = "SYN-UID-001"

        self.assertTrue(validate_event(event)["valid"])

    def test_non_object_rejected(self):
        result = validate_event(None)

        self.assertFalse(result["valid"])
        self.assertIn(
            "invalid_record",
            result["issues"],
        )

    def test_wrong_schema_version(self):
        event = copy.deepcopy(self.event)
        event["schema_version"] = "0.6.0"

        result = validate_event(event)

        self.assertIn(
            "invalid_schema_version",
            result["issues"],
        )

    def test_missing_event_id(self):
        event = copy.deepcopy(self.event)
        event["event_id"] = ""

        result = validate_event(event)

        self.assertIn(
            "missing_event_id",
            result["issues"],
        )

    def test_non_utc_timestamp(self):
        event = copy.deepcopy(self.event)
        event["timestamp_utc"] = (
            "2026-10-10T16:00:00+08:00"
        )

        result = validate_event(event)

        self.assertIn(
            "invalid_timestamp_utc",
            result["issues"],
        )

    def test_invalid_ip_text(self):
        event = copy.deepcopy(self.event)
        event["source"]["ip"] = "999.999.999.999"

        result = validate_event(event)

        self.assertIn(
            "invalid_source_ip",
            result["issues"],
        )

    def test_invalid_port(self):
        event = copy.deepcopy(self.event)
        event["source"]["port"] = 70000

        result = validate_event(event)

        self.assertIn(
            "invalid_source_port",
            result["issues"],
        )

    def test_unhashable_source_type_rejected(self):
        event = copy.deepcopy(self.event)
        event["source_type"] = []

        result = validate_event(event)

        self.assertFalse(result["valid"])
        self.assertIn(
            "unsupported_source_type",
            result["issues"],
        )

    def test_unhashable_event_type_rejected(self):
        event = copy.deepcopy(self.event)
        event["event_type"] = []

        result = validate_event(event)

        self.assertFalse(result["valid"])
        self.assertIn(
            "unsupported_event_type",
            result["issues"],
        )

    def test_uid_must_be_string_or_null(self):
        event = copy.deepcopy(self.event)
        event["uid"] = 12345

        result = validate_event(event)

        self.assertFalse(result["valid"])

    def test_integer_ip_rejected(self):
        event = copy.deepcopy(self.event)
        event["source"]["ip"] = 12345

        result = validate_event(event)

        self.assertFalse(result["valid"])
        self.assertIn(
            "invalid_source_ip",
            result["issues"],
        )

    def test_does_not_mutate_event(self):
        original = copy.deepcopy(self.event)

        validate_event(self.event)

        self.assertEqual(self.event, original)


if __name__ == "__main__":
    unittest.main()
