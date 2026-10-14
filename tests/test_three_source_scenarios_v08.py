"""Scenario contract tests for the V0.8 three-source synthetic study.

Synthetic relationship labels are defined by the experiment, not inferred
from matching IP addresses, ports, host names, or timestamps.
"""

import ipaddress
import sys
import unittest
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from generate_three_source_v08 import generate_dataset


class TestThreeSourceScenariosV08(unittest.TestCase):
    def setUp(self):
        self.data = generate_dataset(repeats=1, seed=20261011)
        self.events = {
            item["event_id"]: item
            for item in self.data["events"]
        }
        self.mappings = {
            item["host"]: item
            for item in self.data["host_mappings"]
        }

    @staticmethod
    def _timestamp(event):
        return datetime.fromisoformat(
            event["timestamp_utc"].replace("Z", "+00:00")
        )

    def _case(self, name):
        label = next(
            item for item in self.data["labels"]
            if item["scenario"] == name
        )
        pair = [self.events[event_id] for event_id in label["event_ids"]]
        zeek = next(item for item in pair if item["source_type"] == "zeek")
        host = next(item for item in pair if item["source_type"] != "zeek")
        mapping = self.mappings[host["host"]["name"]]
        return label, zeek, host, mapping

    def test_positive_controls_have_compatible_network_evidence(self):
        cases = {
            "P01_windows_ipv4": ("windows", 445),
            "P02_linux_ipv4": ("linux", 22),
            "P03_linux_ipv6": ("linux", 22),
        }
        for name, (platform, port) in cases.items():
            with self.subTest(scenario=name):
                label, zeek, host, mapping = self._case(name)
                self.assertIs(label["related"], True)
                self.assertEqual(zeek["event_type"], "zeek.conn")
                self.assertEqual(host["source_type"], platform)
                self.assertEqual(host["outcome"], "failure")
                self.assertEqual(zeek["source"]["ip"], host["source"]["ip"])
                self.assertEqual(zeek["destination"]["ip"], mapping["ip"])
                self.assertEqual(zeek["destination"]["port"], port)
                self.assertIsNone(host["destination"])

    def test_nat_collision_is_not_distinguishable_by_basic_matches(self):
        label, zeek, host, mapping = self._case("N01_nat_collision")
        self.assertIs(label["related"], False)
        self.assertEqual(zeek["source"]["ip"], host["source"]["ip"])
        self.assertEqual(zeek["destination"]["ip"], mapping["ip"])
        self.assertEqual(zeek["destination"]["port"], 445)
        self.assertEqual(
            abs((self._timestamp(zeek) - self._timestamp(host)).total_seconds()),
            45,
        )
        # These matching observations are NOT proof of a shared session.
        self.assertNotIn("related", zeek)
        self.assertNotIn("related", host)

    def test_reversed_direction_swaps_client_and_server(self):
        label, zeek, host, mapping = self._case("N02_reversed_direction")
        self.assertIs(label["related"], False)
        self.assertEqual(zeek["source"]["ip"], mapping["ip"])
        self.assertEqual(zeek["destination"]["ip"], host["source"]["ip"])
        self.assertNotEqual(zeek["source"]["ip"], host["source"]["ip"])
        self.assertEqual(zeek["destination"]["port"], 22)

    def test_wrong_host_mapping_is_a_destination_conflict(self):
        label, zeek, host, mapping = self._case("N03_wrong_host_mapping")
        self.assertIs(label["related"], False)
        self.assertEqual(zeek["source"]["ip"], host["source"]["ip"])
        self.assertNotEqual(zeek["destination"]["ip"], mapping["ip"])
        self.assertEqual(zeek["destination"]["port"], 445)

    def test_all_cases_use_explicit_45_second_offset(self):
        for label in self.data["labels"]:
            with self.subTest(scenario=label["scenario"]):
                _, zeek, host, _ = self._case(label["scenario"])
                delta = (
                    self._timestamp(host) - self._timestamp(zeek)
                ).total_seconds()
                self.assertEqual(delta, 45)

    def test_case_slots_are_separated_across_repetitions(self):
        data = generate_dataset(repeats=2, seed=20261011)
        event_by_id = {event["event_id"]: event for event in data["events"]}
        network_times = []
        for label in data["labels"]:
            zeek = next(
                event_by_id[event_id] for event_id in label["event_ids"]
                if event_by_id[event_id]["source_type"] == "zeek"
            )
            network_times.append(self._timestamp(zeek))
        network_times.sort()
        self.assertEqual(len(network_times), 12)
        for first, second in zip(network_times, network_times[1:]):
            self.assertGreaterEqual((second - first).total_seconds(), 600)

    def test_host_mapping_has_independent_provenance(self):
        for i, mapping in enumerate(self.data["host_mappings"], start=1):
            with self.subTest(host=mapping["host"]):
                self.assertEqual(
                    mapping["provenance"]["filename"],
                    "synthetic-host-mappings.jsonl",
                )
                self.assertEqual(mapping["provenance"]["line_number"], i)
                self.assertIsInstance(ipaddress.ip_address(mapping["ip"]),
                                      (ipaddress.IPv4Address,
                                       ipaddress.IPv6Address))
                self.assertNotIn("related", mapping)

    def test_ipv6_positive_case_uses_ipv6_endpoints_and_mapping(self):
        label, zeek, host, mapping = self._case("P03_linux_ipv6")
        self.assertIs(label["related"], True)
        for value in (
            zeek["source"]["ip"],
            zeek["destination"]["ip"],
            host["source"]["ip"],
            mapping["ip"],
        ):
            self.assertEqual(ipaddress.ip_address(value).version, 6)


if __name__ == "__main__":
    unittest.main()
