
"""Tests for the V0.7 Linux SSH authentication adapter."""

import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from log_analyzer.schema_v07 import validate_event
from log_analyzer.linux_ssh_v07 import normalize_linux_ssh_line


class TestLinuxSSHV07(unittest.TestCase):

    def setUp(self):
        self.line = (
            "2026-10-10T08:00:00Z LAB-LINUX-01 "
            "sshd[421]: Failed password for invalid user "
            "guest from 192.0.2.10 port 53122 ssh2"
        )

    def parse(self, line=None):
        return normalize_linux_ssh_line(
            self.line if line is None else line,
            filename="synthetic-auth.log",
            line_number=1,
        )

    def test_failed_invalid_user(self):
        event = self.parse()

        self.assertEqual(event["event_type"], "linux.ssh_failure")
        self.assertEqual(event["outcome"], "failure")
        self.assertEqual(event["actor"]["name"], "guest")
        self.assertTrue(event["details"]["invalid_user"])
        self.assertTrue(validate_event(event)["valid"])

    def test_failed_known_user(self):
        line = (
            "2026-10-10T08:00:00Z LAB-LINUX-01 "
            "sshd[421]: Failed password for alice "
            "from 192.0.2.10 port 53122 ssh2"
        )

        event = self.parse(line)

        self.assertEqual(event["outcome"], "failure")
        self.assertFalse(event["details"]["invalid_user"])

    def test_accepted_password(self):
        line = (
            "2026-10-10T08:00:00Z LAB-LINUX-01 "
            "sshd[421]: Accepted password for alice "
            "from 192.0.2.10 port 53122 ssh2"
        )

        event = self.parse(line)

        self.assertEqual(event["event_type"], "linux.ssh_success")
        self.assertEqual(event["outcome"], "success")
        self.assertEqual(event["details"]["auth_method"], "password")

    def test_accepted_publickey(self):
        line = (
            "2026-10-10T08:00:00Z LAB-LINUX-01 "
            "sshd[421]: Accepted publickey for alice "
            "from 192.0.2.10 port 53122 ssh2"
        )

        event = self.parse(line)

        self.assertEqual(event["outcome"], "success")
        self.assertEqual(event["details"]["auth_method"], "publickey")

    def test_source_endpoint(self):
        event = self.parse()

        self.assertEqual(
            event["source"],
            {"ip": "192.0.2.10", "port": 53122},
        )

    def test_ipv6_address(self):
        line = self.line.replace(
            "192.0.2.10", "2001:db8::10"
        )

        event = self.parse(line)

        self.assertEqual(
            event["source"]["ip"], "2001:db8::10"
        )

    def test_timezone_conversion(self):
        line = self.line.replace(
            "2026-10-10T08:00:00Z",
            "2026-10-10T16:00:00+08:00",
        )

        event = self.parse(line)

        self.assertEqual(
            event["timestamp_utc"],
            "2026-10-10T08:00:00Z",
        )

    def test_naive_timestamp_rejected(self):
        line = self.line.replace(
            "2026-10-10T08:00:00Z",
            "2026-10-10T08:00:00",
        )

        with self.assertRaises(ValueError):
            self.parse(line)

    def test_invalid_ip_rejected(self):
        line = self.line.replace(
            "192.0.2.10", "999.999.999.999"
        )

        with self.assertRaises(ValueError):
            self.parse(line)

    def test_unrelated_message_rejected(self):
        line = (
            "2026-10-10T08:00:00Z LAB-LINUX-01 "
            "systemd[1]: Started application"
        )

        with self.assertRaises(ValueError):
            self.parse(line)

    def test_provenance(self):
        event = self.parse()

        self.assertEqual(
            event["provenance"],
            {
                "filename": "synthetic-auth.log",
                "line_number": 1,
            },
        )
        self.assertEqual(event["schema_version"], "0.7.0")

    def test_source_string_unchanged(self):
        original = self.line

        self.parse()

        self.assertEqual(self.line, original)


if __name__ == "__main__":
    unittest.main()
