"""Unit tests for explainable security detection."""

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "src")
)

from log_analyzer.correlation import correlate_events
from log_analyzer.detection import detect


BASE = datetime(2026, 9, 11, tzinfo=timezone.utc)
PROTECTED = "10.10.20.0/24"
UNTRUSTED = "10.10.30.0/24"


def event(kind, offset=0, uid="TEST-001",
          src="10.10.20.10", dst="10.10.30.10"):
    timestamp = BASE + timedelta(milliseconds=offset)

    return {
        "event_id": f"{kind}-{offset}",
        "event_type": kind,
        "uid": uid,
        "timestamp_utc": timestamp.isoformat(),
        "source": {"ip": src, "port": 50000},
        "destination": {"ip": dst, "port": 445},
        "details": {
            "note": "TEST::Notice"
            if kind == "zeek.notice" else None
        },
        "provenance": {
            "filename": f"{kind}.log",
            "line_number": 1
        },
    }


def run_detection(events, protected=PROTECTED,
                  untrusted=UNTRUSTED):
    return detect(
        correlate_events(events),
        protected,
        untrusted,
    )


class TestDetection(unittest.TestCase):

    def test_complete_chain_detected(self):
        result = run_detection([
            event("zeek.conn", 0),
            event("zeek.ntlm", 10),
            event("zeek.notice", 13),
        ])
        self.assertEqual(result["summary"]["findings"], 1)
        finding = result["findings"][0]
        self.assertEqual(finding["severity"], "medium")
        self.assertEqual(
            finding["classification"], "requires_investigation"
        )
        self.assertIn(
            "correlated_zeek_notice", finding["signals"]
        )

    def test_ntlm_without_notice_detected(self):
        result = run_detection([
            event("zeek.conn", 0),
            event("zeek.ntlm", 10),
        ])
        self.assertEqual(result["summary"]["findings"], 1)
        self.assertNotIn(
            "correlated_zeek_notice",
            result["findings"][0]["signals"],
        )

    def test_connection_only_skipped(self):
        result = run_detection([event("zeek.conn")])
        self.assertEqual(result["summary"]["findings"], 0)

    def test_ntlm_only_skipped(self):
        result = run_detection([event("zeek.ntlm")])
        self.assertEqual(result["summary"]["findings"], 0)

    def test_mismatched_uid_skipped(self):
        result = run_detection([
            event("zeek.conn", 0, uid="A"),
            event("zeek.ntlm", 10, uid="B"),
        ])
        self.assertEqual(result["summary"]["findings"], 0)

    def test_outside_protected_network(self):
        result = run_detection([
            event("zeek.conn", src="10.10.99.10"),
            event("zeek.ntlm", 10, src="10.10.99.10"),
        ])
        self.assertEqual(result["summary"]["findings"], 0)

    def test_outside_untrusted_network(self):
        result = run_detection([
            event("zeek.conn", dst="192.0.2.10"),
            event("zeek.ntlm", 10, dst="192.0.2.10"),
        ])
        self.assertEqual(result["summary"]["findings"], 0)

    def test_conflicting_addresses(self):
        result = run_detection([
            event("zeek.conn", 0),
            event("zeek.ntlm", 10, src="10.10.20.99"),
        ])
        self.assertEqual(result["summary"]["findings"], 0)

    def test_excessive_time_window(self):
        result = run_detection([
            event("zeek.conn", 0),
            event("zeek.ntlm", 301000),
        ])
        self.assertEqual(result["summary"]["findings"], 0)

    def test_reverse_order_without_notice(self):
        result = run_detection([
            event("zeek.conn", 20000),
            event("zeek.ntlm", 0),
        ])
        self.assertEqual(result["summary"]["findings"], 0)

    def test_missing_uid(self):
        result = run_detection([
            event("zeek.conn", 0, uid=None),
            event("zeek.ntlm", 10, uid=None),
        ])
        self.assertEqual(result["summary"]["findings"], 0)

    def test_invalid_network_configuration(self):
        with self.assertRaises(ValueError):
            run_detection(
                [event("zeek.conn")],
                protected="invalid-network",
            )


if __name__ == "__main__":
    unittest.main()