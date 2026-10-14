"""Boundary tests for the V0.8 three-source candidate engine.

Unknown protocol and missing ports are incomplete evidence.
They must not be represented as confirmed network sessions.
"""

import copy
import ipaddress
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from generate_three_source_v08 import generate_dataset
from log_analyzer.three_source_v08 import find_three_source_candidates


class TestThreeSourceBoundariesV08(unittest.TestCase):

    def setUp(self):
        self.data = generate_dataset(repeats=1, seed=20261011)
        self.events = self.data["events"]
        self.mappings = self.data["host_mappings"]

    def find(self, events=None, mappings=None):
        return find_three_source_candidates(
            self.events if events is None else events,
            self.mappings if mappings is None else mappings,
        )

    def get_event(self, events, scenario, source_type):
        label = next(
            x for x in self.data["labels"]
            if x["scenario"] == scenario
        )
        return next(
            x for x in events
            if x["event_id"] in label["event_ids"]
            and x["source_type"] == source_type
        )

    def test_missing_protocol_remains_only_a_candidate(self):
        zeek = self.get_event(
            self.events, "P02_linux_ipv4", "zeek"
        )
        self.assertNotIn("proto", zeek["details"])

        candidates = self.find()
        self.assertEqual(len(candidates), 4)

        for candidate in candidates:
            self.assertEqual(
                candidate["interpretation"],
                "candidate_evidence_association",
            )
            self.assertNotIn("confirmed_session", candidate)

    def test_explicit_tcp_accepts_case_variants(self):
        events = copy.deepcopy(self.events)
        zeek = self.get_event(
            events, "P02_linux_ipv4", "zeek"
        )
        zeek["details"]["proto"] = " TCP "

        self.assertEqual(len(self.find(events=events)), 4)

    def test_invalid_protocol_type_is_not_matched(self):
        events = copy.deepcopy(self.events)
        zeek = self.get_event(
            events, "P02_linux_ipv4", "zeek"
        )
        zeek["details"]["proto"] = ["tcp"]

        self.assertEqual(len(self.find(events=events)), 3)

    def test_missing_zeek_source_port_is_unknown(self):
        events = copy.deepcopy(self.events)
        zeek = self.get_event(
            events, "P02_linux_ipv4", "zeek"
        )
        zeek["source"]["port"] = None

        self.assertEqual(len(self.find(events=events)), 4)

    def test_zero_host_source_port_is_unknown(self):
        events = copy.deepcopy(self.events)
        linux = self.get_event(
            events, "P02_linux_ipv4", "linux"
        )
        linux["source"]["port"] = 0

        self.assertEqual(len(self.find(events=events)), 4)

    def test_equivalent_ipv6_mapping_is_accepted(self):
        mappings = copy.deepcopy(self.mappings)
        linux = self.get_event(
            self.events, "P03_linux_ipv6", "linux"
        )
        host_name = linux["host"]["name"]

        mapping = next(
            x for x in mappings if x["host"] == host_name
        )
        mapping["ip"] = ipaddress.ip_address(
            mapping["ip"]
        ).exploded

        self.assertEqual(len(self.find(mappings=mappings)), 4)

    def test_invalid_mapping_addresses_are_rejected(self):
        invalid_ips = (
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "ff02::1",
            None,
            [],
        )

        for bad_ip in invalid_ips:
            with self.subTest(ip=bad_ip):
                mappings = copy.deepcopy(self.mappings)
                mappings[0]["ip"] = bad_ip

                with self.assertRaises(ValueError):
                    self.find(mappings=mappings)

    def test_repeated_cases_remain_independent(self):
        data = generate_dataset(
            repeats=2, seed=20261011
        )

        candidates = self.find(
            events=data["events"],
            mappings=data["host_mappings"],
        )

        self.assertEqual(len(candidates), 8)

        pairs = [
            tuple(item["event_ids"])
            for item in candidates
        ]
        self.assertEqual(len(pairs), len(set(pairs)))


if __name__ == "__main__":
    unittest.main()
