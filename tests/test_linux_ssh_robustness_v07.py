
"""Robustness tests for the V0.7 Linux SSH adapter."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from log_analyzer.linux_ssh_v07 import normalize_linux_ssh_line


class TestLinuxSSHRobustnessV07(unittest.TestCase):

    def setUp(self):
        self.line = (
            "2026-10-10T08:00:00Z LAB-LINUX-01 "
            "sshd[421]: Failed password for invalid user "
            "guest from 192.0.2.10 port 53122 ssh2"
        )

    def parse(self, line=None, **kwargs):
        options = {
            "filename": "synthetic-auth.log",
            "line_number": 1,
        }
        options.update(kwargs)

        return normalize_linux_ssh_line(
            self.line if line is None else line,
            **options,
        )

    def test_empty_line_rejected(self):
        with self.assertRaises(ValueError):
            self.parse("")

    def test_non_string_line_rejected(self):
        with self.assertRaises(ValueError):
            self.parse({"unexpected": "object"})

    def test_missing_filename_rejected(self):
        with self.assertRaises(ValueError):
            self.parse(filename="")

    def test_boolean_line_number_rejected(self):
        with self.assertRaises(ValueError):
            self.parse(line_number=True)

    def test_legacy_syslog_without_timezone_rejected(self):
        line = (
            "Oct 10 08:00:00 LAB-LINUX-01 "
            "sshd[421]: Failed password for guest "
            "from 192.0.2.10 port 53122 ssh2"
        )

        with self.assertRaises(ValueError):
            self.parse(line)

    def test_invalid_timezone_rejected(self):
        line = self.line.replace(
            "2026-10-10T08:00:00Z",
            "2026-10-10T08:00:00+25:00",
        )

        with self.assertRaises(ValueError):
            self.parse(line)

    def test_zero_source_port_rejected(self):
        line = self.line.replace(
            "port 53122", "port 0"
        )

        with self.assertRaises(ValueError):
            self.parse(line)

    def test_source_port_out_of_range_rejected(self):
        line = self.line.replace(
            "port 53122", "port 65536"
        )

        with self.assertRaises(ValueError):
            self.parse(line)

    def test_accepted_invalid_user_rejected(self):
        line = self.line.replace(
            "Failed password",
            "Accepted password",
        )

        with self.assertRaises(ValueError):
            self.parse(line)

    def test_zero_sshd_pid_rejected(self):
        line = self.line.replace(
            "sshd[421]", "sshd[0]"
        )

        with self.assertRaises(ValueError):
            self.parse(line)

    def test_unspecified_ipv4_rejected(self):
        line = self.line.replace(
            "192.0.2.10", "0.0.0.0"
        )

        with self.assertRaises(ValueError):
            self.parse(line)

    def test_unspecified_ipv6_rejected(self):
        line = self.line.replace(
            "192.0.2.10", "::"
        )

        with self.assertRaises(ValueError):
            self.parse(line)


if __name__ == "__main__":
    unittest.main()
