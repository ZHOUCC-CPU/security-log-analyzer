
"""Tests for the deterministic V0.8 three-source dataset."""

import ipaddress
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from log_analyzer.schema_v07 import validate_event
from generate_three_source_v08 import generate_dataset


SCENARIOS = {
    "P01_windows_ipv4",
    "P02_linux_ipv4",
    "P03_linux_ipv6",
    "N01_nat_collision",
    "N02_reversed_direction",
    "N03_wrong_host_mapping",
}


class TestThreeSourceDatasetV08(unittest.TestCase):

    def setUp(self):
        self.dataset = generate_dataset(
            repeats=1,
            seed=20261011,
        )

    def test_deterministic_generation(self):
        other = generate_dataset(
            repeats=1,
            seed=20261011,
        )
        self.assertEqual(self.dataset, other)

    def test_scenario_inventory(self):
        scenarios = {
            label["scenario"]
            for label in self.dataset["labels"]
        }
        self.assertEqual(scenarios, SCENARIOS)

    def test_counts_and_manifest(self):
        data = self.dataset

        self.assertEqual(len(data["events"]), 12)
        self.assertEqual(len(data["labels"]), 6)

        positives = sum(
            label["related"] is True
            for label in data["labels"]
        )
        negatives = sum(
            label["related"] is False
            for label in data["labels"]
        )

        self.assertEqual(positives, 3)
        self.assertEqual(negatives, 3)

        manifest = data["manifest"]
        self.assertEqual(
            manifest["schema_version"], "0.7.0"
        )
        self.assertEqual(manifest["seed"], 20261011)
        self.assertEqual(manifest["repeats"], 1)
        self.assertEqual(manifest["event_count"], 12)
        self.assertEqual(manifest["label_count"], 6)
        self.assertIs(
            manifest["production_accuracy_claim"], False
        )

    def test_three_source_coverage(self):
        source_types = {
            event["source_type"]
            for event in self.dataset["events"]
        }

        self.assertEqual(
            source_types,
            {"zeek", "windows", "linux"},
        )

    def test_every_event_passes_schema(self):
        for event in self.dataset["events"]:
            with self.subTest(event_id=event["event_id"]):
                result = validate_event(event)
                self.assertTrue(
                    result["valid"], result["issues"]
                )

    def test_labels_reference_unique_events(self):
        events = self.dataset["events"]
        ids = [event["event_id"] for event in events]

        self.assertEqual(len(ids), len(set(ids)))

        known = set(ids)
        events_by_id = {
            event["event_id"]: event
            for event in events
        }

        for label in self.dataset["labels"]:
            with self.subTest(case_id=label["case_id"]):
                pair = label["event_ids"]
                self.assertEqual(len(pair), 2)
                self.assertEqual(len(set(pair)), 2)
                self.assertTrue(set(pair) <= known)

                types = {
                    events_by_id[event_id]["source_type"]
                    for event_id in pair
                }

                self.assertIn("zeek", types)
                self.assertEqual(len(types), 2)

    def test_explicit_host_mappings(self):
        mappings = self.dataset["host_mappings"]

        self.assertTrue(mappings)

        mapped_hosts = set()

        for mapping in mappings:
            host = mapping["host"]
            address = mapping["ip"]
            provenance = mapping["provenance"]

            self.assertIsInstance(host, str)
            self.assertTrue(host.strip())
            ipaddress.ip_address(address)

            self.assertTrue(
                provenance["filename"].strip()
            )
            self.assertGreater(
                provenance["line_number"], 0
            )

            mapped_hosts.add(host)

        host_events = [
            event for event in self.dataset["events"]
            if event["source_type"] in ("windows", "linux")
        ]

        for event in host_events:
            self.assertIn(
                event["host"]["name"],
                mapped_hosts,
            )
            # The adapter does not supply a destination IP.
            self.assertIsNone(event["destination"])

    def test_nat_collision_is_negative_control(self):
        label = next(
            label for label in self.dataset["labels"]
            if label["scenario"] == "N01_nat_collision"
        )

        self.assertIs(label["related"], False)

        events_by_id = {
            event["event_id"]: event
            for event in self.dataset["events"]
        }

        pair = [
            events_by_id[event_id]
            for event_id in label["event_ids"]
        ]

        zeek = next(
            event for event in pair
            if event["source_type"] == "zeek"
        )
        host = next(
            event for event in pair
            if event["source_type"] != "zeek"
        )

        # Same observed client IP does not prove a
        # relationship when NAT or shared addresses exist.
        self.assertEqual(
            zeek["source"]["ip"],
            host["source"]["ip"],
        )

    def test_labels_not_leaked_into_evidence(self):
        forbidden = {
            "related",
            "ground_truth",
            "scenario",
            "case_id",
        }

        for event in self.dataset["events"]:
            self.assertTrue(
                forbidden.isdisjoint(event.keys())
            )
            self.assertTrue(
                forbidden.isdisjoint(
                    event.get("details", {}).keys()
                )
            )

        for mapping in self.dataset["host_mappings"]:
            self.assertTrue(
                forbidden.isdisjoint(mapping.keys())
            )

    def test_repeats_scale_without_id_collisions(self):
        data = generate_dataset(
            repeats=2,
            seed=20261011,
        )

        self.assertEqual(len(data["events"]), 24)
        self.assertEqual(len(data["labels"]), 12)

        ids = [
            event["event_id"]
            for event in data["events"]
        ]
        self.assertEqual(len(ids), len(set(ids)))

    def test_invalid_repeats_rejected(self):
        for value in (0, -1, True, 1.5, "2", None):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    generate_dataset(repeats=value)


if __name__ == "__main__":
    unittest.main()
