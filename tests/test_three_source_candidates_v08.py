"""TDD contract for V0.8 Zeek-to-host authentication candidates.

These are investigative co-occurrences, never confirmed sessions or attacks.
Synthetic relationship labels MUST NOT be passed to the association engine.
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


class TestThreeSourceCandidatesV08(unittest.TestCase):
    def setUp(self):
        data = generate_dataset(repeats=1, seed=20261011)
        self.events = data["events"]
        self.mappings = data["host_mappings"]
        self.labels = {label["scenario"]: label for label in data["labels"]}

    def find(self, events=None, mappings=None, **kwargs):
        return find_three_source_candidates(
            self.events if events is None else events,
            self.mappings if mappings is None else mappings,
            **kwargs,
        )

    def pair(self, scenario):
        ids = self.labels[scenario]["event_ids"]
        records = [event for event in self.events if event["event_id"] in ids]
        zeek = next(event for event in records if event["source_type"] == "zeek")
        host = next(event for event in records if event["source_type"] != "zeek")
        return zeek, host

    @staticmethod
    def pairs(candidates):
        return {tuple(item["event_ids"]) for item in candidates}

    def test_positive_controls_and_nat_candidate(self):
        candidates = self.find()
        expected_scenarios = (
            "P01_windows_ipv4", "P02_linux_ipv4",
            "P03_linux_ipv6", "N01_nat_collision",
        )
        expected = {
            tuple(self.labels[name]["event_ids"])
            for name in expected_scenarios
        }
        self.assertEqual(len(candidates), 4)
        self.assertEqual(self.pairs(candidates), expected)

        # N01 is deliberately unrelated in the synthetic ground truth.
        # It is indistinguishable using the allowed evidence fields;
        # the engine must NOT peek at the label to discard it.
        self.assertIs(self.labels["N01_nat_collision"]["related"], False)

    def test_candidate_is_explicitly_not_an_attack_verdict(self):
        for candidate in self.find():
            self.assertEqual(candidate["type"], "zeek_host_auth_cooccurrence")
            self.assertEqual(
                candidate["interpretation"], "candidate_evidence_association"
            )
            self.assertNotIn("malicious", candidate)
            self.assertNotIn("related", candidate)
            self.assertNotIn("ground_truth", candidate)
            self.assertNotIn("scenario", candidate)
            self.assertEqual(len(candidate["event_ids"]), 2)

    def test_reversed_direction_and_wrong_mapping_do_not_match(self):
        candidates = self.pairs(self.find())
        for name in ("N02_reversed_direction", "N03_wrong_host_mapping"):
            with self.subTest(scenario=name):
                self.assertNotIn(tuple(self.labels[name]["event_ids"]), candidates)

    def test_missing_mapping_does_not_infer_destination(self):
        _, host = self.pair("P01_windows_ipv4")
        host_name = host["host"]["name"]
        mappings = [m for m in self.mappings if m["host"] != host_name]
        candidates = self.find(mappings=mappings)
        self.assertNotIn(
            tuple(self.labels["P01_windows_ipv4"]["event_ids"]),
            self.pairs(candidates),
        )
        self.assertEqual(len(candidates), 3)

    def test_source_ip_mismatch_does_not_match(self):
        events = copy.deepcopy(self.events)
        target = self.pair("P02_linux_ipv4")[1]["event_id"]
        record = next(x for x in events if x["event_id"] == target)
        record["source"]["ip"] = "192.0.2.201"
        self.assertEqual(len(self.find(events=events)), 3)

    def test_service_port_must_be_explicitly_compatible(self):
        events = copy.deepcopy(self.events)
        target = self.pair("P02_linux_ipv4")[0]["event_id"]
        record = next(x for x in events if x["event_id"] == target)
        record["destination"]["port"] = 445  # SSH case is port 22 only.
        self.assertEqual(len(self.find(events=events)), 3)

    def test_only_failed_host_authentication_is_eligible(self):
        for event_type, outcome in (
            ("windows.login_success", "success"),
            ("windows.special_privileges", None),
        ):
            with self.subTest(event_type=event_type):
                events = copy.deepcopy(self.events)
                target = self.pair("P01_windows_ipv4")[1]["event_id"]
                host = next(x for x in events if x["event_id"] == target)
                host["event_type"] = event_type
                host["outcome"] = outcome
                self.assertEqual(len(self.find(events=events)), 3)

    def test_time_boundary_is_inclusive(self):
        self.assertEqual(len(self.find(window_seconds=45)), 4)
        self.assertEqual(len(self.find(window_seconds=44)), 0)
        self.assertEqual(len(self.find(window_seconds=120)), 4)

    def test_ipv6_equivalent_text_forms_match(self):
        events = copy.deepcopy(self.events)
        host_id = self.pair("P03_linux_ipv6")[1]["event_id"]
        host = next(x for x in events if x["event_id"] == host_id)
        host["source"]["ip"] = ipaddress.ip_address(
            host["source"]["ip"]
        ).exploded
        self.assertIn(
            tuple(self.labels["P03_linux_ipv6"]["event_ids"]),
            self.pairs(self.find(events=events)),
        )

    def test_candidate_carries_three_independent_provenances(self):
        candidates = self.find()
        by_pair = {tuple(item["event_ids"]): item for item in candidates}
        name = "P01_windows_ipv4"
        zeek, host = self.pair(name)
        mapping = next(
            m for m in self.mappings if m["host"] == host["host"]["name"]
        )
        evidence = by_pair[tuple(self.labels[name]["event_ids"])]["evidence"]
        self.assertEqual(evidence["zeek_provenance"], zeek["provenance"])
        self.assertEqual(evidence["host_provenance"], host["provenance"])
        self.assertEqual(
            evidence["host_mapping_provenance"], mapping["provenance"]
        )
        self.assertEqual(evidence["time_delta_seconds"], 45)
        self.assertEqual(evidence["server_port"], 445)
        self.assertEqual(evidence["host_name"], host["host"]["name"])
        self.assertEqual(evidence["network_uid"], zeek["uid"])

    def test_input_immutability_and_evidence_detachment(self):
        before_events = copy.deepcopy(self.events)
        before_maps = copy.deepcopy(self.mappings)
        candidates = self.find()
        self.assertEqual(self.events, before_events)
        self.assertEqual(self.mappings, before_maps)
        candidates[0]["evidence"]["host_mapping_provenance"]["filename"] = "changed"
        self.assertEqual(self.mappings, before_maps)

    def test_event_order_mapping_order_and_identical_duplicates(self):
        expected = self.find()
        self.assertEqual(
            self.find(events=list(reversed(self.events)),
                      mappings=list(reversed(self.mappings))),
            expected,
        )
        events_with_duplicate = self.events + [copy.deepcopy(self.events[0])]
        self.assertEqual(self.find(events=events_with_duplicate), expected)

    def test_conflicting_duplicate_event_id_is_error(self):
        conflicting = copy.deepcopy(self.events[0])
        conflicting["timestamp_utc"] = "2026-10-11T09:00:00Z"
        with self.assertRaises(ValueError):
            self.find(events=self.events + [conflicting])

    def test_conflicting_host_mapping_is_error(self):
        conflicting = copy.deepcopy(self.mappings[0])
        conflicting["ip"] = "192.0.2.200"
        with self.assertRaises(ValueError):
            self.find(mappings=self.mappings + [conflicting])

    def test_malformed_records_and_window_are_errors(self):
        invalid = copy.deepcopy(self.events)
        invalid[0]["event_id"] = None
        with self.assertRaises(ValueError):
            self.find(events=invalid)
        bad_mapping = copy.deepcopy(self.mappings)
        bad_mapping[0]["provenance"]["line_number"] = 0
        with self.assertRaises(ValueError):
            self.find(mappings=bad_mapping)
        for value in (-1, True, None, float("nan"), float("inf")):
            with self.subTest(window_seconds=value):
                with self.assertRaises(ValueError):
                    self.find(window_seconds=value)


if __name__ == "__main__":
    unittest.main()
