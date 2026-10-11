
"""Robustness tests for the V0.8 Zeek schema adapter."""

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from log_analyzer.zeek_parser import normalize_record
from log_analyzer.zeek_adapter_v08 import adapt_zeek_event
from log_analyzer.schema_v07 import validate_event


class TestZeekAdapterRobustnessV08(unittest.TestCase):

    def setUp(self):
        record = {
            "ts": "1791612800.0",
            "uid": "Csynthetic001",
            "id.orig_h": "192.0.2.10",
            "id.orig_p": "53122",
            "id.resp_h": "198.51.100.20",
            "id.resp_p": "445",
        }

        self.legacy = normalize_record(
            record,
            Path("synthetic-conn.log"),
            7,
            '{"synthetic":true}',
            "conn",
        )

    def adapt(self, event=None):
        if event is None:
            event = self.legacy
        return adapt_zeek_event(event)

    def test_unhashable_event_type_rejected_cleanly(self):
        event = copy.deepcopy(self.legacy)
        event["event_type"] = ["zeek.conn"]

        with self.assertRaises(ValueError):
            self.adapt(event)

    def test_explicit_null_schema_version_rejected(self):
        event = copy.deepcopy(self.legacy)
        event["schema_version"] = None

        with self.assertRaises(ValueError):
            self.adapt(event)

    def test_empty_provenance_filename_rejected(self):
        event = copy.deepcopy(self.legacy)
        event["provenance"]["filename"] = ""

        with self.assertRaises(ValueError):
            self.adapt(event)

    def test_zero_provenance_line_number_rejected(self):
        event = copy.deepcopy(self.legacy)
        event["provenance"]["line_number"] = 0

        with self.assertRaises(ValueError):
            self.adapt(event)

    def test_missing_provenance_rejected(self):
        event = copy.deepcopy(self.legacy)
        event["provenance"] = None

        with self.assertRaises(ValueError):
            self.adapt(event)

    def test_invalid_details_rejected(self):
        event = copy.deepcopy(self.legacy)
        event["details"] = ["unexpected", "list"]

        with self.assertRaises(ValueError):
            self.adapt(event)

    def test_invalid_destination_port_rejected(self):
        event = copy.deepcopy(self.legacy)
        event["destination"]["port"] = 65536

        with self.assertRaises(ValueError):
            self.adapt(event)

    def test_invalid_uid_type_rejected(self):
        event = copy.deepcopy(self.legacy)
        event["uid"] = {"unexpected": "object"}

        with self.assertRaises(ValueError):
            self.adapt(event)

    def test_incompatible_schema_version_rejected(self):
        event = copy.deepcopy(self.legacy)
        event["schema_version"] = "0.6.0"

        with self.assertRaises(ValueError):
            self.adapt(event)

    def test_missing_endpoint_not_fabricated(self):
        event = copy.deepcopy(self.legacy)
        event["source"] = {
            "ip": None,
            "port": None,
        }

        adapted = self.adapt(event)

        self.assertIsNone(adapted["source"]["ip"])
        self.assertIsNone(adapted["source"]["port"])
        self.assertTrue(validate_event(adapted)["valid"])

    def test_nested_endpoints_detached(self):
        original = copy.deepcopy(self.legacy)

        adapted = self.adapt()
        adapted["source"]["ip"] = "203.0.113.10"

        self.assertEqual(self.legacy, original)

    def test_rejected_input_not_modified(self):
        event = copy.deepcopy(self.legacy)
        event["event_type"] = "zeek.dns"

        original = copy.deepcopy(event)

        with self.assertRaises(ValueError):
            self.adapt(event)

        self.assertEqual(event, original)


if __name__ == "__main__":
    unittest.main()
