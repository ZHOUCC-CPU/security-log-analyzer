
"""Tests for V0.7 cross-source candidate associations."""

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from log_analyzer.cross_source_v07 import (
    find_cross_source_candidates,
)


def make_event(
    source_type,
    event_id,
    timestamp,
    source_ip="192.0.2.10",
    username="guest",
):
    event_type = (
        "windows.login_failure"
        if source_type == "windows"
        else "linux.ssh_failure"
    )

    return {
        "schema_version": "0.7.0",
        "event_id": event_id,
        "timestamp_utc": timestamp,
        "source_type": source_type,
        "event_type": event_type,
        "uid": None,
        "source": (
            {"ip": source_ip, "port": 53122}
            if source_ip is not None
            else None
        ),
        "destination": None,
        "host": {"name": f"LAB-{source_type.upper()}"},
        "actor": (
            {"name": username, "domain": None}
            if username is not None
            else None
        ),
        "outcome": "failure",
        "details": {},
        "provenance": {
            "filename": f"synthetic-{source_type}.jsonl",
            "line_number": 1,
        },
    }


class TestCrossSourceV07(unittest.TestCase):

    def setUp(self):
        self.windows = make_event(
            "windows",
            "WIN-001",
            "2026-10-10T08:00:00Z",
        )

        self.linux = make_event(
            "linux",
            "LINUX-001",
            "2026-10-10T08:00:45Z",
        )

    def candidates(self, *events):
        return find_cross_source_candidates(
            list(events),
            window_seconds=120,
        )

    def test_matching_failures_create_candidate(self):
        results = self.candidates(self.windows, self.linux)

        self.assertEqual(len(results), 1)

        candidate = results[0]

        self.assertEqual(
            set(candidate["event_ids"]),
            {"WIN-001", "LINUX-001"},
        )

        self.assertEqual(
            candidate["type"],
            "shared_source_auth_failure",
        )

        self.assertEqual(
            candidate["interpretation"],
            "co-occurrence_only",
        )

        self.assertEqual(
            candidate["evidence"]["source_ip"],
            "192.0.2.10",
        )

        self.assertEqual(
            candidate["evidence"]["username"],
            "guest",
        )

        self.assertEqual(
            candidate["evidence"]["time_delta_seconds"],
            45,
        )

    def test_different_source_ip_not_associated(self):
        linux = copy.deepcopy(self.linux)
        linux["source"]["ip"] = "192.0.2.99"

        self.assertEqual(
            self.candidates(self.windows, linux), []
        )

    def test_different_username_not_associated(self):
        linux = copy.deepcopy(self.linux)
        linux["actor"]["name"] = "alice"

        self.assertEqual(
            self.candidates(self.windows, linux), []
        )

    def test_outside_time_window_not_associated(self):
        linux = copy.deepcopy(self.linux)
        linux["timestamp_utc"] = "2026-10-10T08:03:00Z"

        self.assertEqual(
            self.candidates(self.windows, linux), []
        )

    def test_time_window_boundary_included(self):
        linux = copy.deepcopy(self.linux)
        linux["timestamp_utc"] = "2026-10-10T08:02:00Z"

        self.assertEqual(
            len(self.candidates(self.windows, linux)),
            1,
        )

    def test_missing_source_ip_not_associated(self):
        windows = copy.deepcopy(self.windows)
        windows["source"] = None

        self.assertEqual(
            self.candidates(windows, self.linux), []
        )

    def test_success_event_not_in_failure_rule(self):
        windows = copy.deepcopy(self.windows)
        windows["event_type"] = "windows.login_success"
        windows["outcome"] = "success"

        self.assertEqual(
            self.candidates(windows, self.linux), []
        )

    def test_privilege_event_not_in_failure_rule(self):
        windows = copy.deepcopy(self.windows)
        windows["event_type"] = "windows.special_privileges"
        windows["outcome"] = None
        windows["source"] = None

        self.assertEqual(
            self.candidates(windows, self.linux), []
        )

    def test_order_independent(self):
        forward = self.candidates(
            self.windows, self.linux
        )

        reverse = self.candidates(
            self.linux, self.windows
        )

        self.assertEqual(forward, reverse)

    def test_duplicate_records_do_not_repeat_candidate(self):
        results = self.candidates(
            self.windows,
            self.linux,
            copy.deepcopy(self.windows),
        )

        self.assertEqual(len(results), 1)

    def test_invalid_timestamp_is_processing_error(self):
        linux = copy.deepcopy(self.linux)
        linux["timestamp_utc"] = "not-a-timestamp"

        with self.assertRaises(ValueError):
            self.candidates(self.windows, linux)

    def test_does_not_modify_input(self):
        events = [self.windows, self.linux]
        original = copy.deepcopy(events)

        find_cross_source_candidates(events)

        self.assertEqual(events, original)


if __name__ == "__main__":
    unittest.main()
