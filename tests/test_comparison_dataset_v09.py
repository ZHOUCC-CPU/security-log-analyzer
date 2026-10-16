"""V0.9 expanded synthetic dataset research contract."""

import ipaddress
import sys
import unittest
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from generate_three_source_v08 import generate_dataset
from generate_comparison_v09 import generate_expanded_dataset
from log_analyzer.schema_v07 import validate_event


SCENARIOS = {
    "P01_windows_ipv4": True,
    "P02_linux_ipv4": True,
    "P03_linux_ipv6": True,
    "N01_nat_collision": False,
    "N02_reversed_direction": False,
    "N03_wrong_host_mapping": False,
    "P04_boundary_120": True,
    "P05_outside_120": True,
    "P06_unknown_client_port": True,
    "P07_port_translation": True,
    "P08_missing_zeek_source_ip": True,
    "N04_wrong_service_port": False,
    "N05_udp_protocol": False,
    "N06_wrong_client_port": False,
    "N07_source_ip_mismatch": False,
    "N08_ipv6_host_mapping_conflict": False,
}


class TestComparisonDatasetV09(unittest.TestCase):

    def setUp(self):
        self.dataset = generate_expanded_dataset()
        self.events = {
            e["event_id"]: e for e in self.dataset["events"]
        }
        self.labels = {
            x["scenario"]: x for x in self.dataset["labels"]
        }
        self.mappings = {
            x["host"]: x for x in self.dataset["host_mappings"]
        }

    def pair(self, scenario):
        ids = self.labels[scenario]["event_ids"]
        records = [self.events[i] for i in ids]
        zeek = next(x for x in records if x["source_type"] == "zeek")
        host = next(x for x in records if x["source_type"] != "zeek")
        return zeek, host

    def test_expected_scenarios_and_counts(self):
        d = self.dataset
        self.assertEqual(set(self.labels), set(SCENARIOS))
        self.assertEqual(len(d["events"]), 32)
        self.assertEqual(len(d["labels"]), 16)
        self.assertEqual(len(d["host_mappings"]), 16)
        for scenario, related in SCENARIOS.items():
            self.assertIs(self.labels[scenario]["related"], related)

    def test_frozen_v08_prefix_preserved(self):
        old = generate_dataset(repeats=1, seed=20261011)
        for key in ("events", "labels", "host_mappings"):
            with self.subTest(key=key):
                self.assertEqual(
                    self.dataset[key][:len(old[key])], old[key]
                )

    def test_unique_ids_and_valid_events(self):
        ids = [e["event_id"] for e in self.dataset["events"]]
        cases = [x["case_id"] for x in self.dataset["labels"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(cases), len(set(cases)))
        for event in self.dataset["events"]:
            self.assertTrue(validate_event(event)["valid"])
        for label in self.dataset["labels"]:
            self.assertEqual(len(label["event_ids"]), 2)
            self.assertTrue(set(label["event_ids"]) <= set(ids))

    def test_labels_do_not_leak_into_observations(self):
        for record in (
            self.dataset["events"] + self.dataset["host_mappings"]
        ):
            for field in ("related", "scenario", "case_id"):
                self.assertNotIn(field, record)

    def test_deterministic_generation(self):
        first = generate_expanded_dataset(seed=20261011)
        second = generate_expanded_dataset(seed=20261011)
        self.assertEqual(first, second)

    def test_repetitions_have_unique_ids(self):
        data = generate_expanded_dataset(repeats=2)
        self.assertEqual(len(data["events"]), 64)
        self.assertEqual(len(data["labels"]), 32)
        self.assertEqual(len(data["host_mappings"]), 32)
        self.assertEqual(
            len({e["event_id"] for e in data["events"]}), 64
        )
        self.assertEqual(
            len({x["case_id"] for x in data["labels"]}), 32
        )

    def test_time_boundary_controls(self):
        for scenario, expected in (
            ("P04_boundary_120", 120),
            ("P05_outside_120", 121),
        ):
            zeek, host = self.pair(scenario)
            a = datetime.fromisoformat(
                zeek["timestamp_utc"].replace("Z", "+00:00")
            )
            b = datetime.fromisoformat(
                host["timestamp_utc"].replace("Z", "+00:00")
            )
            self.assertEqual(abs((b - a).total_seconds()), expected)

    def test_related_missing_evidence_controls(self):
        zeek, host = self.pair("P06_unknown_client_port")
        self.assertIn(zeek["source"]["port"], (None, 0))

        zeek, host = self.pair("P07_port_translation")
        self.assertNotEqual(
            zeek["source"]["port"], host["source"]["port"]
        )
        self.assertGreater(zeek["source"]["port"], 0)
        self.assertGreater(host["source"]["port"], 0)

        zeek, host = self.pair("P08_missing_zeek_source_ip")
        self.assertIsNone(zeek["source"]["ip"])
        self.assertIsNotNone(host["source"]["ip"])

    def test_negative_evidence_controls(self):
        zeek, host = self.pair("N04_wrong_service_port")
        self.assertNotEqual(
            zeek["destination"]["port"],
            445 if host["source_type"] == "windows" else 22
        )

        zeek, host = self.pair("N05_udp_protocol")
        self.assertEqual(
            zeek["details"]["proto"].lower(), "udp"
        )

        zeek, host = self.pair("N06_wrong_client_port")
        self.assertNotEqual(
            zeek["source"]["port"], host["source"]["port"]
        )

        zeek, host = self.pair("N07_source_ip_mismatch")
        self.assertNotEqual(
            zeek["source"]["ip"], host["source"]["ip"]
        )

        zeek, host = self.pair(
            "N08_ipv6_host_mapping_conflict"
        )
        mapping = self.mappings[host["host"]["name"]]
        self.assertEqual(
            ipaddress.ip_address(
                zeek["destination"]["ip"]
            ).version, 6
        )
        self.assertNotEqual(
            zeek["destination"]["ip"], mapping["ip"]
        )

    def test_all_case_pairs_use_zeek_and_one_host(self):
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario):
                zeek, host = self.pair(scenario)
                self.assertEqual(zeek["source_type"], "zeek")
                self.assertIn(
                    host["source_type"], ("windows", "linux")
                )
                self.assertIn(host["host"]["name"], self.mappings)


if __name__ == "__main__":
    unittest.main()
