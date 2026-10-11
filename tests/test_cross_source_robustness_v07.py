
"""Robustness tests for V0.7 cross-source correlation."""

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from log_analyzer.cross_source_v07 import (
    find_cross_source_candidates,
)


def make_event(source_type, event_id, timestamp):
    if source_type == "windows":
        event_type = "windows.login_failure"
    else:
        event_type = "linux.ssh_failure"

    return {
        "schema_version": "0.7.0",
        "event_id": event_id,
        "timestamp_utc": timestamp,
        "source_type": source_type,
        "event_type": event_type,
        "uid": None,
        "source": {
            "ip": "192.0.2.10",
            "port": 53122,
        },
        "destination": None,
        "host": {
            "name": f"LAB-{source_type.upper()}",
        },
        "actor": {
            "name": "guest",
            "domain": None,
        },
        "outcome": "failure",
        "details": {},
        "provenance": {
            "filename": f"synthetic-{source_type}.jsonl",
            "line_number": 1,
        },
    }


class TestCrossSourceRobustnessV07(unittest.TestCase):

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

    def candidates(self, *events, window_seconds=120):
        return find_cross_source_candidates(
            list(events),
            window_seconds=window_seconds,
        )

    def test_unspecified_ipv4_not_associated(self):
        windows = copy.deepcopy(self.windows)
        linux = copy.deepcopy(self.linux)

        windows["source"]["ip"] = "0.0.0.0"
        linux["source"]["ip"] = "0.0.0.0"

        self.assertEqual(
            self.candidates(windows, linux), []
        )

    def test_multicast_ipv4_not_associated(self):
        windows = copy.deepcopy(self.windows)
        linux = copy.deepcopy(self.linux)

        windows["source"]["ip"] = "224.0.0.1"
        linux["source"]["ip"] = "224.0.0.1"

        self.assertEqual(
            self.candidates(windows, linux), []
        )

    def test_broadcast_ipv4_not_associated(self):
        windows = copy.deepcopy(self.windows)
        linux = copy.deepcopy(self.linux)

        windows["source"]["ip"] = "255.255.255.255"
        linux["source"]["ip"] = "255.255.255.255"

        self.assertEqual(
            self.candidates(windows, linux), []
        )

    def test_multicast_ipv6_not_associated(self):
        windows = copy.deepcopy(self.windows)
        linux = copy.deepcopy(self.linux)

        windows["source"]["ip"] = "ff02::1"
        linux["source"]["ip"] = "ff02::1"

        self.assertEqual(
            self.candidates(windows, linux), []
        )

    def test_conflicting_event_id_rejected(self):
        conflicting = copy.deepcopy(self.windows)
        conflicting["timestamp_utc"] = (
            "2026-10-10T08:01:00Z"
        )

        with self.assertRaises(ValueError):
            self.candidates(
                self.windows,
                conflicting,
                self.linux,
            )

    def test_identical_duplicate_deduplicated(self):
        results = self.candidates(
            self.windows,
            self.linux,
            copy.deepcopy(self.windows),
            copy.deepcopy(self.linux),
        )

        self.assertEqual(len(results), 1)

    def test_inconsistent_outcome_not_associated(self):
        windows = copy.deepcopy(self.windows)
        windows["outcome"] = "success"

        self.assertEqual(
            self.candidates(windows, self.linux), []
        )

    def test_missing_actor_not_associated(self):
        windows = copy.deepcopy(self.windows)
        windows["actor"] = None

        self.assertEqual(
            self.candidates(windows, self.linux), []
        )

    def test_invalid_time_windows_rejected(self):
        invalid_values = [
            -1,
            float("nan"),
            float("inf"),
            True,
            "120",
            None,
        ]

        for value in invalid_values:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    self.candidates(
                        self.windows,
                        self.linux,
                        window_seconds=value,
                    )

    def test_same_source_type_not_associated(self):
        second_windows = make_event(
            "windows",
            "WIN-002",
            "2026-10-10T08:00:45Z",
        )

        self.assertEqual(
            self.candidates(
                self.windows,
                second_windows,
            ),
            [],
        )

    def test_shared_ip_does_not_prove_attack(self):
        # Shared IP and account identity may occur behind NAT.
        # This test intentionally permits a co-occurrence
        # candidate but requires a non-attack interpretation.
        results = self.candidates(
            self.windows,
            self.linux,
        )

        self.assertEqual(len(results), 1)
        self.assertEqual(
            results[0]["interpretation"],
            "co-occurrence_only",
        )


if __name__ == "__main__":
    unittest.main()
