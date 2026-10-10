"""Tests for strict evidence endpoint integrity in V0.6."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from log_analyzer.correlation import correlate_events
from log_analyzer.detection import detect


def make_event(kind, milliseconds, source_ip="10.10.20.10"):
    return {
        "event_id": f"{kind}-{milliseconds}",
        "event_type": f"zeek.{kind}",
        "uid": "V06-TEST-001",
        "timestamp_utc": (
            f"2026-10-10T00:00:00.{milliseconds:03d}Z"
        ),
        "source": {
            "ip": source_ip,
            "port": 50000,
        },
        "destination": {
            "ip": "10.10.30.10",
            "port": 445,
        },
        "details": {},
        "provenance": {
            "filename": f"{kind}.log",
            "line_number": 1,
        },
    }


def findings(events):
    correlation = correlate_events(events)
    report = detect(
        correlation,
        "10.10.20.0/24",
        "10.10.30.0/24",
    )
    return report["summary"]["findings"]


class TestEndpointIntegrityV06(unittest.TestCase):

    def test_missing_ntlm_source_must_not_alert(self):
        events = [
            make_event("conn", 0),
            make_event("ntlm", 10),
        ]

        events[1]["source"]["ip"] = None

        self.assertEqual(findings(events), 0)

    def test_missing_ntlm_destination_must_not_alert(self):
        events = [
            make_event("conn", 0),
            make_event("ntlm", 10),
        ]

        events[1]["destination"]["ip"] = None

        self.assertEqual(findings(events), 0)

    def test_conflict_cannot_be_hidden_by_missing_ip(self):
        events = [
            make_event("conn", 0),
            make_event(
                "ntlm",
                10,
                source_ip="10.10.20.240",
            ),
        ]

        # Original evidence contains a source IP conflict.
        self.assertEqual(findings(events), 0)

        # Removing the conflicting IP must not create an alert.
        events[1]["source"]["ip"] = None

        self.assertEqual(findings(events), 0)

    def test_optional_notice_endpoint_may_be_missing(self):
        events = [
            make_event("conn", 0),
            make_event("ntlm", 10),
            make_event("notice", 13),
        ]

        events[2]["source"]["ip"] = None

        # Conn and NTLM still contain complete matching endpoints.
        self.assertEqual(findings(events), 1)


if __name__ == "__main__":
    unittest.main()