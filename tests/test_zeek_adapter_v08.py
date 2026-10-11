
"""Tests for the V0.8 Zeek-to-unified-schema adapter."""

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from log_analyzer.zeek_parser import normalize_record
from log_analyzer.schema_v07 import validate_event
from log_analyzer.zeek_adapter_v08 import adapt_zeek_event


class TestZeekAdapterV08(unittest.TestCase):

    def setUp(self):
        # Generate a genuine legacy-format event using
        # the existing Zeek normalizer.
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

    def test_conn_event_passes_schema(self):
        event = self.adapt()

        self.assertEqual(
            event["schema_version"], "0.7.0"
        )
        self.assertEqual(
            event["source_type"], "zeek"
        )
        self.assertEqual(
            event["event_type"], "zeek.conn"
        )
        self.assertTrue(validate_event(event)["valid"])

    def test_ntlm_event_passes_schema(self):
        legacy = copy.deepcopy(self.legacy)
        legacy["event_type"] = "zeek.ntlm"

        event = self.adapt(legacy)

        self.assertTrue(validate_event(event)["valid"])
        self.assertEqual(event["event_type"], "zeek.ntlm")

    def test_notice_event_passes_schema(self):
        legacy = copy.deepcopy(self.legacy)
        legacy["event_type"] = "zeek.notice"

        event = self.adapt(legacy)

        self.assertTrue(validate_event(event)["valid"])
        self.assertEqual(event["event_type"], "zeek.notice")

    def test_event_id_and_uid_preserved(self):
        event = self.adapt()

        self.assertEqual(
            event["event_id"],
            self.legacy["event_id"],
        )
        self.assertEqual(
            event["uid"],
            self.legacy["uid"],
        )

    def test_endpoints_preserved(self):
        event = self.adapt()

        self.assertEqual(
            event["source"],
            self.legacy["source"],
        )
        self.assertEqual(
            event["destination"],
            self.legacy["destination"],
        )

    def test_provenance_preserved(self):
        event = self.adapt()

        self.assertEqual(
            event["provenance"],
            self.legacy["provenance"],
        )

    def test_missing_uid_not_invented(self):
        legacy = copy.deepcopy(self.legacy)
        legacy["uid"] = None

        event = self.adapt(legacy)

        self.assertIsNone(event["uid"])
        self.assertTrue(validate_event(event)["valid"])

    def test_host_actor_outcome_not_invented(self):
        event = self.adapt()

        self.assertIsNone(event["host"])
        self.assertIsNone(event["actor"])
        self.assertIsNone(event["outcome"])

    def test_input_not_modified(self):
        original = copy.deepcopy(self.legacy)

        self.adapt()

        self.assertEqual(self.legacy, original)

    def test_nested_details_are_detached(self):
        event = self.adapt()
        original = copy.deepcopy(self.legacy)

        event["details"]["synthetic_test_change"] = True

        self.assertEqual(self.legacy, original)

    def test_non_object_rejected(self):
        with self.assertRaises(ValueError):
            self.adapt(["invalid", "record"])

    def test_unsupported_zeek_type_rejected(self):
        legacy = copy.deepcopy(self.legacy)
        legacy["event_type"] = "zeek.dns"

        with self.assertRaises(ValueError):
            self.adapt(legacy)

    def test_invalid_timestamp_rejected(self):
        legacy = copy.deepcopy(self.legacy)
        legacy["timestamp_utc"] = (
            "2026-10-10T08:00:00"
        )

        with self.assertRaises(ValueError):
            self.adapt(legacy)

    def test_invalid_source_ip_rejected(self):
        legacy = copy.deepcopy(self.legacy)
        legacy["source"]["ip"] = (
            "999.999.999.999"
        )

        with self.assertRaises(ValueError):
            self.adapt(legacy)


if __name__ == "__main__":
    unittest.main()
