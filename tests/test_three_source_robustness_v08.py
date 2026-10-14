"""V0.8 robustness tests for Zeek-to-host candidate association."""

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from generate_three_source_v08 import generate_dataset
from log_analyzer.three_source_v08 import find_three_source_candidates


class TestThreeSourceRobustnessV08(unittest.TestCase):

    def setUp(self):
        self.data = generate_dataset(repeats=1, seed=20261011)
        self.events = self.data["events"]
        self.mappings = self.data["host_mappings"]

    def find(self, events=None, mappings=None):
        return find_three_source_candidates(
            self.events if events is None else events,
            self.mappings if mappings is None else mappings,
        )

    def event(self, scenario, source_type):
        label = next(
            x for x in self.data["labels"]
            if x["scenario"] == scenario
        )
        return next(
            x for x in self.events
            if x["event_id"] in label["event_ids"]
            and x["source_type"] == source_type
        )

    def test_explicit_tcp_connection_remains_candidate(self):
        events = copy.deepcopy(self.events)
        target = self.event("P02_linux_ipv4", "zeek")

        record = next(
            x for x in events if x["event_id"] == target["event_id"]
        )
        record["details"]["proto"] = "tcp"

        self.assertEqual(len(self.find(events=events)), 4)

    def test_udp_connection_must_not_match_ssh(self):
        events = copy.deepcopy(self.events)
        target = self.event("P02_linux_ipv4", "zeek")

        record = next(
            x for x in events if x["event_id"] == target["event_id"]
        )
        record["details"]["proto"] = "udp"

        self.assertEqual(len(self.find(events=events)), 3)

    def test_conflicting_client_ports_do_not_match(self):
        events = copy.deepcopy(self.events)
        target = self.event("P02_linux_ipv4", "linux")

        record = next(
            x for x in events if x["event_id"] == target["event_id"]
        )
        record["source"]["port"] = 53123

        self.assertEqual(len(self.find(events=events)), 3)

    def test_windows_remote_interactive_login_is_excluded(self):
        events = copy.deepcopy(self.events)
        target = self.event("P01_windows_ipv4", "windows")

        record = next(
            x for x in events if x["event_id"] == target["event_id"]
        )
        record["details"]["logon_type"] = 10

        self.assertEqual(len(self.find(events=events)), 3)

    def test_linux_success_is_not_failed_authentication(self):
        events = copy.deepcopy(self.events)
        target = self.event("P02_linux_ipv4", "linux")

        record = next(
            x for x in events if x["event_id"] == target["event_id"]
        )
        record["event_type"] = "linux.ssh_success"
        record["outcome"] = "success"

        self.assertEqual(len(self.find(events=events)), 3)

    def test_zeek_ntlm_record_is_not_connection_record(self):
        events = copy.deepcopy(self.events)
        target = self.event("P01_windows_ipv4", "zeek")

        record = next(
            x for x in events if x["event_id"] == target["event_id"]
        )
        record["event_type"] = "zeek.ntlm"

        self.assertEqual(len(self.find(events=events)), 3)

    def test_missing_network_destination_is_not_inferred(self):
        events = copy.deepcopy(self.events)
        target = self.event("P01_windows_ipv4", "zeek")

        record = next(
            x for x in events if x["event_id"] == target["event_id"]
        )
        record["destination"]["ip"] = None

        self.assertEqual(len(self.find(events=events)), 3)

    def test_identical_duplicate_host_mapping_is_safe(self):
        mappings = copy.deepcopy(self.mappings)
        mappings.append(copy.deepcopy(mappings[0]))

        self.assertEqual(
            self.find(mappings=mappings),
            self.find(),
        )


if __name__ == "__main__":
    unittest.main()
