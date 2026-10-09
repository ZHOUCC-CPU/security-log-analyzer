"""Unit tests for security event correlation."""

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "src"),
)

from log_analyzer.correlation import correlate_events


BASE_TIME = datetime(
    2026, 9, 11, 5, 41, 48,
    tzinfo=timezone.utc,
)


def make_event(
    event_type,
    offset_ms,
    uid="TEST-UID",
    source_ip="10.10.20.10",
    destination_ip="10.10.30.10",
):
    timestamp = BASE_TIME + timedelta(
        milliseconds=offset_ms
    )

    return {
        "event_id": f"{event_type}-{offset_ms}",
        "event_type": event_type,
        "uid": uid,
        "timestamp_utc": timestamp.isoformat().replace(
            "+00:00", "Z"
        ),
        "source": {"ip": source_ip, "port": 50000},
        "destination": {"ip": destination_ip, "port": 445},
        "details": {
            "note": "TEST::Alert"
            if event_type == "zeek.notice"
            else None
        },
        "provenance": {
            "filename": event_type + ".log",
            "line_number": 1,
        },
    }


class TestCorrelation(unittest.TestCase):

    def complete_events(self):
        return [
            make_event("zeek.conn", 0),
            make_event("zeek.ntlm", 10),
            make_event("zeek.notice", 13),
        ]

    def test_complete_chain(self):
        result = correlate_events(self.complete_events())

        self.assertEqual(
            result["summary"]["complete_chains"], 1
        )
        self.assertEqual(
            result["chains"][0]["status"],
            "complete_chain",
        )
        self.assertEqual(
            result["chains"][0]["duration_ms"], 13
        )
        self.assertEqual(
            len(result["chains"][0]["evidence"]), 3
        )

    def test_connection_only(self):
        events = [make_event("zeek.conn", 0)]

        result = correlate_events(events)

        self.assertEqual(
            result["chains"][0]["status"],
            "connection_only",
        )

    def test_mismatched_uid(self):
        events = [
            make_event("zeek.conn", 0, uid="UID-A"),
            make_event("zeek.ntlm", 10, uid="UID-B"),
            make_event("zeek.notice", 13, uid="UID-B"),
        ]

        result = correlate_events(events)

        self.assertEqual(
            result["summary"]["complete_chains"], 0
        )
        self.assertEqual(
            result["summary"]["total_groups"], 2
        )

    def test_inconsistent_ip(self):
        events = self.complete_events()

        events[1]["source"]["ip"] = "10.10.99.99"

        result = correlate_events(events)

        self.assertEqual(
            result["chains"][0]["status"],
            "requires_review",
        )
        self.assertFalse(
            result["chains"][0]["consistent_endpoints"]
        )

    def test_wrong_event_order(self):
        events = [
            make_event("zeek.conn", 30000),
            make_event("zeek.ntlm", 20000),
            make_event("zeek.notice", 10000),
        ]

        result = correlate_events(events)

        self.assertEqual(
            result["chains"][0]["status"],
            "requires_review",
        )
        self.assertFalse(
            result["chains"][0]["chronological"]
        )

    def test_exceeds_time_window(self):
        events = [
            make_event("zeek.conn", 0),
            make_event("zeek.ntlm", 301000),
            make_event("zeek.notice", 302000),
        ]

        result = correlate_events(events)

        self.assertEqual(
            result["chains"][0]["status"],
            "requires_review",
        )
        self.assertFalse(
            result["chains"][0]["within_time_window"]
        )

    def test_missing_notice(self):
        events = [
            make_event("zeek.conn", 0),
            make_event("zeek.ntlm", 10),
        ]

        result = correlate_events(events)

        self.assertEqual(
            result["chains"][0]["status"],
            "ntlm_without_notice",
        )

    def test_missing_uid(self):
        events = [
            make_event("zeek.conn", 0, uid=None),
            make_event("zeek.ntlm", 10, uid=None),
            make_event("zeek.notice", 13, uid=None),
        ]

        result = correlate_events(events)

        self.assertEqual(
            result["summary"]["total_groups"], 3
        )
        self.assertEqual(
            result["summary"]["complete_chains"], 0
        )

    def test_unsorted_input(self):
        events = list(reversed(self.complete_events()))

        result = correlate_events(events)

        self.assertEqual(
            result["summary"]["complete_chains"], 1
        )
        self.assertEqual(
            result["chains"][0]["duration_ms"], 13
        )

    def test_timestamp_without_timezone(self):
        events = self.complete_events()
        events[0]["timestamp_utc"] = "2026-09-11T05:41:48"

        with self.assertRaises(ValueError):
            correlate_events(events)


if __name__ == "__main__":
    unittest.main()