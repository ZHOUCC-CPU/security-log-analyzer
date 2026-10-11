
"""Tests for the deterministic V0.7 cross-source dataset."""

import sys
import unittest
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from log_analyzer.schema_v07 import validate_event
from generate_cross_source_v07 import generate_dataset


SCENARIOS = {
    "P01_shared_activity",
    "P02_ipv6_shared_activity",
    "P03_time_boundary",
    "P04_delayed_related_activity",
    "N01_different_ip",
    "N02_different_username",
    "N03_unrelated_outside_window",
    "N04_nat_collision",
    "N05_shared_account_collision",
    "N06_missing_endpoint",
    "N07_success_not_failure",
    "N08_multicast_source",
}


class TestCrossSourceDatasetV07(unittest.TestCase):

    def setUp(self):
        self.dataset = generate_dataset(
            repeats=1,
            seed=20261010,
        )

    def test_deterministic_generation(self):
        other = generate_dataset(
            repeats=1,
            seed=20261010,
        )

        self.assertEqual(self.dataset, other)

    def test_expected_scenario_inventory(self):
        scenarios = {
            label["scenario"]
            for label in self.dataset["labels"]
        }

        self.assertEqual(scenarios, SCENARIOS)

    def test_label_distribution(self):
        labels = self.dataset["labels"]

        positives = sum(
            label["related"] is True
            for label in labels
        )

        negatives = sum(
            label["related"] is False
            for label in labels
        )

        self.assertEqual(positives, 4)
        self.assertEqual(negatives, 8)

    def test_event_and_label_counts(self):
        self.assertEqual(
            len(self.dataset["events"]), 24
        )
        self.assertEqual(
            len(self.dataset["labels"]), 12
        )

        manifest = self.dataset["manifest"]

        self.assertEqual(manifest["event_count"], 24)
        self.assertEqual(manifest["label_count"], 12)
        self.assertEqual(manifest["schema_version"], "0.7.0")
        self.assertEqual(manifest["seed"], 20261010)
        self.assertEqual(manifest["repeats"], 1)

    def test_all_events_pass_schema_validation(self):
        for event in self.dataset["events"]:
            with self.subTest(event_id=event["event_id"]):
                result = validate_event(event)
                self.assertTrue(result["valid"], result["issues"])

    def test_labels_reference_existing_events(self):
        ids = [
            event["event_id"]
            for event in self.dataset["events"]
        ]

        self.assertEqual(len(ids), len(set(ids)))

        known_ids = set(ids)

        for label in self.dataset["labels"]:
            with self.subTest(case_id=label["case_id"]):
                self.assertEqual(len(label["event_ids"]), 2)
                self.assertNotEqual(
                    label["event_ids"][0],
                    label["event_ids"][1],
                )

                for event_id in label["event_ids"]:
                    self.assertIn(event_id, known_ids)

    def test_nat_collision_is_negative(self):
        label = next(
            item for item in self.dataset["labels"]
            if item["scenario"] == "N04_nat_collision"
        )

        self.assertIs(label["related"], False)

        events_by_id = {
            event["event_id"]: event
            for event in self.dataset["events"]
        }

        first, second = (
            events_by_id[event_id]
            for event_id in label["event_ids"]
        )

        self.assertEqual(
            first["source"]["ip"],
            second["source"]["ip"],
        )
        self.assertEqual(
            first["actor"]["name"],
            second["actor"]["name"],
        )

        t1 = datetime.fromisoformat(
            first["timestamp_utc"].replace("Z", "+00:00")
        )
        t2 = datetime.fromisoformat(
            second["timestamp_utc"].replace("Z", "+00:00")
        )

        self.assertLessEqual(
            abs((t1 - t2).total_seconds()),
            120,
        )

    def test_delayed_related_activity(self):
        label = next(
            item for item in self.dataset["labels"]
            if item["scenario"] == "P04_delayed_related_activity"
        )

        self.assertIs(label["related"], True)

        events_by_id = {
            event["event_id"]: event
            for event in self.dataset["events"]
        }

        first, second = (
            events_by_id[event_id]
            for event_id in label["event_ids"]
        )

        t1 = datetime.fromisoformat(
            first["timestamp_utc"].replace("Z", "+00:00")
        )
        t2 = datetime.fromisoformat(
            second["timestamp_utc"].replace("Z", "+00:00")
        )

        self.assertGreater(
            abs((t1 - t2).total_seconds()),
            120,
        )

    def test_repeats_scale_without_id_collisions(self):
        dataset = generate_dataset(
            repeats=2,
            seed=20261010,
        )

        self.assertEqual(len(dataset["events"]), 48)
        self.assertEqual(len(dataset["labels"]), 24)

        ids = [
            event["event_id"]
            for event in dataset["events"]
        ]

        self.assertEqual(len(ids), len(set(ids)))

    def test_invalid_repeat_counts_rejected(self):
        for value in (0, -1, True, 1.5, "2", None):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    generate_dataset(repeats=value)

    def test_labels_do_not_leak_into_events(self):
        for event in self.dataset["events"]:
            self.assertNotIn("related", event)
            self.assertNotIn("ground_truth", event)
            self.assertNotIn("scenario", event)


if __name__ == "__main__":
    unittest.main()
