
"""End-to-end integration tests for the V0.8 Zeek adapter."""

import copy
import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from log_analyzer.zeek_parser import (
    ZeekParseError,
    parse_zeek,
)
from log_analyzer.zeek_adapter_v08 import adapt_zeek_event
from log_analyzer.schema_v07 import validate_event


class TestZeekIntegrationV08(unittest.TestCase):

    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def record(self, uid="Csynthetic001"):
        return {
            "ts": 1791612800.0,
            "uid": uid,
            "id.orig_h": "192.0.2.10",
            "id.orig_p": 53122,
            "id.resp_h": "198.51.100.20",
            "id.resp_p": 445,
        }

    def write_json(self, filename, records):
        path = self.directory / filename

        text = "".join(
            json.dumps(record) + "\n"
            for record in records
        )

        path.write_text(text, encoding="utf-8")
        return path

    def test_json_conn_log_end_to_end(self):
        path = self.write_json(
            "conn.log", [self.record()]
        )

        parsed = list(parse_zeek(path))
        self.assertEqual(len(parsed), 1)

        adapted = adapt_zeek_event(parsed[0])

        self.assertTrue(validate_event(adapted)["valid"])
        self.assertEqual(adapted["event_type"], "zeek.conn")
        self.assertEqual(adapted["uid"], "Csynthetic001")
        self.assertEqual(adapted["destination"]["port"], 445)
        self.assertEqual(
            adapted["provenance"]["filename"], "conn.log"
        )

    def test_ascii_conn_log_end_to_end(self):
        path = self.directory / "conn.log"

        fields = (
            "ts\tuid\tid.orig_h\tid.orig_p\t"
            "id.resp_h\tid.resp_p"
        )

        values = (
            "1791612800.0\tCsynthetic002\t"
            "192.0.2.10\t53122\t"
            "198.51.100.20\t445"
        )

        text = (
            "#separator \\x09\n"
            "#fields\t" + fields + "\n"
            + values + "\n"
        )

        path.write_text(text, encoding="utf-8")

        parsed = list(parse_zeek(path))
        self.assertEqual(len(parsed), 1)

        adapted = adapt_zeek_event(parsed[0])

        self.assertTrue(validate_event(adapted)["valid"])
        self.assertEqual(adapted["uid"], "Csynthetic002")
        self.assertEqual(adapted["source"]["port"], 53122)
        self.assertEqual(adapted["destination"]["port"], 445)

    def test_ntlm_and_notice_logs_end_to_end(self):
        for filename, expected_type in (
            ("ntlm.log", "zeek.ntlm"),
            ("notice.log", "zeek.notice"),
        ):
            with self.subTest(filename=filename):
                path = self.write_json(
                    filename, [self.record()]
                )

                parsed = list(parse_zeek(path))
                adapted = adapt_zeek_event(parsed[0])

                self.assertEqual(
                    adapted["event_type"], expected_type
                )
                self.assertTrue(
                    validate_event(adapted)["valid"]
                )

    def test_multiple_records_keep_unique_evidence(self):
        path = self.write_json(
            "conn.log",
            [
                self.record("Csynthetic001"),
                self.record("Csynthetic002"),
            ],
        )

        parsed = list(parse_zeek(path))
        originals = copy.deepcopy(parsed)

        adapted = [
            adapt_zeek_event(event)
            for event in parsed
        ]

        self.assertEqual(len(adapted), 2)
        self.assertNotEqual(
            adapted[0]["event_id"],
            adapted[1]["event_id"],
        )

        self.assertEqual(
            [
                event["provenance"]["line_number"]
                for event in adapted
            ],
            [1, 2],
        )

        self.assertEqual(parsed, originals)

    def test_invalid_timestamp_rejected_by_parser(self):
        invalid = self.record()
        invalid["ts"] = "not-a-timestamp"

        path = self.write_json(
            "conn.log", [invalid]
        )

        with self.assertRaises(ZeekParseError):
            list(parse_zeek(path))

    def test_invalid_ip_rejected_by_adapter(self):
        invalid = self.record()
        invalid["id.orig_h"] = "999.999.999.999"

        path = self.write_json(
            "conn.log", [invalid]
        )

        parsed = list(parse_zeek(path))
        self.assertEqual(len(parsed), 1)

        with self.assertRaises(ValueError):
            adapt_zeek_event(parsed[0])


if __name__ == "__main__":
    unittest.main()
