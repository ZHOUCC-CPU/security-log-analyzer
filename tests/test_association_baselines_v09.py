"""TDD contract for V0.9 candidate association baselines."""

import copy
import math
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from generate_three_source_v08 import generate_dataset
from log_analyzer.association_baselines_v09 import (
    find_time_only_pairs,
    find_ip_time_pairs,
)


class TestAssociationBaselinesV09(unittest.TestCase):

    def setUp(self):
        self.dataset = generate_dataset(repeats=1, seed=20261011)
        self.events = self.dataset["events"]
        self.labels = {
            item["scenario"]: tuple(item["event_ids"])
            for item in self.dataset["labels"]
        }

    def test_time_only_predicts_six_pairs(self):
        actual = find_time_only_pairs(self.events)
        self.assertEqual(set(actual), set(self.labels.values()))
        self.assertEqual(len(actual), 6)

    def test_ip_time_predicts_five_pairs(self):
        actual = set(find_ip_time_pairs(self.events))
        expected = set(self.labels.values()) - {
            self.labels["N02_reversed_direction"]
        }
        self.assertEqual(actual, expected)

    def test_ip_time_retains_ambiguous_negatives(self):
        actual = set(find_ip_time_pairs(self.events))
        self.assertIn(self.labels["N01_nat_collision"], actual)
        self.assertIn(self.labels["N03_wrong_host_mapping"], actual)

    def test_window_44_excludes_all_pairs(self):
        self.assertEqual(
            find_time_only_pairs(self.events, window_seconds=44),
            [],
        )
        self.assertEqual(
            find_ip_time_pairs(self.events, window_seconds=44),
            [],
        )

    def test_window_45_is_inclusive(self):
        self.assertEqual(
            len(find_time_only_pairs(
                self.events, window_seconds=45
            )),
            6,
        )
        self.assertEqual(
            len(find_ip_time_pairs(
                self.events, window_seconds=45
            )),
            5,
        )

    def test_input_order_does_not_change_results(self):
        reversed_events = list(reversed(self.events))
        for method in (find_time_only_pairs, find_ip_time_pairs):
            with self.subTest(method=method.__name__):
                self.assertEqual(
                    method(self.events),
                    method(reversed_events),
                )

    def test_events_are_not_mutated(self):
        original = copy.deepcopy(self.events)
        find_time_only_pairs(self.events)
        find_ip_time_pairs(self.events)
        self.assertEqual(self.events, original)

    def test_invalid_windows_are_rejected(self):
        for window in (-1, True, "120", math.nan, math.inf):
            for method in (
                find_time_only_pairs,
                find_ip_time_pairs,
            ):
                with self.subTest(
                    window=window,
                    method=method.__name__,
                ):
                    with self.assertRaises(ValueError):
                        method(
                            self.events,
                            window_seconds=window,
                        )

    def test_invalid_event_is_rejected(self):
        events = copy.deepcopy(self.events)
        events[0]["timestamp_utc"] = "invalid-time"
        for method in (find_time_only_pairs, find_ip_time_pairs):
            with self.subTest(method=method.__name__):
                with self.assertRaises(ValueError):
                    method(events)

    def test_conflicting_duplicate_id_is_rejected(self):
        events = copy.deepcopy(self.events)
        duplicate = copy.deepcopy(events[0])
        duplicate["source"]["ip"] = "198.18.99.99"
        events.append(duplicate)
        for method in (find_time_only_pairs, find_ip_time_pairs):
            with self.subTest(method=method.__name__):
                with self.assertRaises(ValueError):
                    method(events)

    def test_identical_duplicates_do_not_add_pairs(self):
        events = copy.deepcopy(self.events)
        events.append(copy.deepcopy(events[0]))
        for method in (find_time_only_pairs, find_ip_time_pairs):
            with self.subTest(method=method.__name__):
                self.assertEqual(
                    method(events),
                    method(self.events),
                )


if __name__ == "__main__":
    unittest.main()
