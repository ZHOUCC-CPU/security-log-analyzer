"""Unit tests for the Zeek log parser."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "src"),
)

from log_analyzer.zeek_parser import ZeekParseError, parse_zeek


class TestZeekParser(unittest.TestCase):

    def parse_sample(self, content):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "conn.log"
            path.write_text(content, encoding="utf-8")
            return list(parse_zeek(path))

    def test_ascii_zeek(self):
        content = (
            "#separator \\x09\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\t"
            "id.resp_h\tid.resp_p\tproto\tservice\n"
            "1760000000.0\tC001\t10.10.20.10\t50000\t"
            "10.10.30.10\t445\ttcp\tsmb\n"
        )

        events = self.parse_sample(content)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["uid"], "C001")
        self.assertEqual(events[0]["destination"]["port"], 445)
        self.assertEqual(events[0]["source_type"], "zeek")

    def test_json_zeek(self):
        record = {
            "ts": 1760000000.0,
            "uid": "C002",
            "id.orig_h": "10.10.20.10",
            "id.resp_h": "10.10.30.10",
            "id.resp_p": 445,
        }

        events = self.parse_sample(json.dumps(record))

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["uid"], "C002")

    def test_unset_value(self):
        content = (
            "#separator \\x09\n"
            "#fields\tts\tuid\tservice\n"
            "1760000000.0\tC003\t-\n"
        )

        events = self.parse_sample(content)

        self.assertIsNone(events[0]["details"]["service"])

    def test_column_mismatch(self):
        content = (
            "#separator \\x09\n"
            "#fields\tts\tuid\n"
            "1760000000.0\n"
        )

        with self.assertRaises(ZeekParseError):
            self.parse_sample(content)

    def test_invalid_timestamp(self):
        content = (
            "#separator \\x09\n"
            "#fields\tts\tuid\n"
            "invalid\tC004\n"
        )

        with self.assertRaises(ZeekParseError):
            self.parse_sample(content)

    def test_missing_header(self):
        with self.assertRaises(ZeekParseError):
            self.parse_sample("1760000000.0\tC005\n")


if __name__ == "__main__":
    unittest.main()