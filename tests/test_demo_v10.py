"""TDD contract for the V1.0 offline demonstration."""

import json
import shutil
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from demo_v10 import run_demo


class TestDemoV10(unittest.TestCase):

    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        folder = Path(self.temp.name)
        source = ROOT / "docs/evidence/v0.9"

        self.events = folder / "events.jsonl"
        self.mappings = folder / "host-mappings.jsonl"
        self.output = folder / "demo-report.json"

        shutil.copyfile(source / "events.jsonl", self.events)
        shutil.copyfile(
            source / "host-mappings.jsonl",
            self.mappings,
        )

        # No labels are copied into the demonstration folder.

    def run_demo(self, output=None):
        return run_demo(
            self.events,
            self.mappings,
            output or self.output,
            window_seconds=120,
        )

    def test_complete_offline_demonstration(self):
        result = self.run_demo()

        self.assertEqual(result["demo_version"], "v1.0")
        self.assertEqual(result["input_format"], "normalized_jsonl")
        self.assertIs(result["normalization_performed"], False)
        self.assertEqual(result["schema_version"], "0.7.0")
        self.assertEqual(result["event_count"], 32)
        self.assertEqual(result["host_mapping_count"], 16)
        self.assertEqual(result["candidate_pair_count"], 6)

        saved = json.loads(self.output.read_text("utf-8"))
        self.assertEqual(saved, result)

    def test_candidate_provenance_and_interpretation(self):
        result = self.run_demo()
        candidates = result["candidates"]

        self.assertEqual(len(candidates), 6)

        for candidate in candidates:
            self.assertEqual(
                candidate["interpretation"],
                "candidate_evidence_association",
            )
            self.assertEqual(len(candidate["event_ids"]), 2)

            evidence = candidate["evidence"]
            self.assertIn("zeek_provenance", evidence)
            self.assertIn("host_provenance", evidence)
            self.assertIn("host_mapping_provenance", evidence)

    def test_demo_does_not_require_or_publish_labels(self):
        result = self.run_demo()

        self.assertFalse(
            (self.events.parent / "labels.jsonl").exists()
        )

        for forbidden in (
            "labels", "related", "classification",
            "precision", "recall", "f1",
        ):
            self.assertNotIn(forbidden, result)

        for candidate in result["candidates"]:
            self.assertNotIn("related", candidate)
            self.assertNotIn("classification", candidate)

    def test_repeated_runs_produce_identical_bytes(self):
        first = self.run_demo()

        second_path = self.output.parent / "second.json"
        second = self.run_demo(second_path)

        self.assertEqual(first, second)
        self.assertEqual(
            self.output.read_bytes(),
            second_path.read_bytes(),
        )

    def test_invalid_json_is_rejected_without_output(self):
        self.events.write_text('{"event_id":', encoding="utf-8")

        with self.assertRaises(ValueError):
            self.run_demo()

        self.assertFalse(self.output.exists())

    def test_invalid_schema_is_rejected_without_output(self):
        lines = self.events.read_text("utf-8").splitlines()
        event = json.loads(lines[0])
        event["schema_version"] = "invalid"
        lines[0] = json.dumps(event)

        self.events.write_text(
            "\n".join(lines) + "\n",
            encoding="utf-8",
        )

        with self.assertRaises(ValueError):
            self.run_demo()

        self.assertFalse(self.output.exists())

    def test_existing_report_cannot_be_overwritten(self):
        self.output.write_text(
            "PROTECTED", encoding="utf-8"
        )

        with self.assertRaises(FileExistsError):
            self.run_demo()

        self.assertEqual(
            self.output.read_text("utf-8"), "PROTECTED"
        )


    def test_missing_protocol_is_explicitly_reported(self):
        result = self.run_demo()

        self.assertEqual(
            result["protocol_not_recorded_candidate_count"],
            6,
        )

        for candidate in result["candidates"]:
            self.assertEqual(
                candidate["evidence"]["protocol_status"],
                "not_recorded",
            )

    def test_explicit_tcp_is_distinguished_from_missing(self):
        records = [
            json.loads(line)
            for line in self.events.read_text("utf-8").splitlines()
            if line.strip()
        ]

        network = next(
            item for item in records
            if item["source_type"] == "zeek"
        )

        target_id = network["event_id"]
        network["details"]["proto"] = "tcp"

        self.events.write_text(
            "\n".join(
                json.dumps(item, sort_keys=True)
                for item in records
            ) + "\n",
            encoding="utf-8",
        )

        result = self.run_demo()

        statuses = {
            candidate["event_ids"][0]:
            candidate["evidence"]["protocol_status"]
            for candidate in result["candidates"]
        }

        self.assertEqual(len(statuses), 6)
        self.assertEqual(statuses[target_id], "explicit_tcp")

        self.assertEqual(
            sum(
                status == "not_recorded"
                for status in statuses.values()
            ),
            5,
        )

        self.assertEqual(
            result["protocol_not_recorded_candidate_count"],
            5,
        )


    def test_empty_events_are_rejected(self):
        self.events.write_text("", encoding="utf-8")

        with self.assertRaises(ValueError):
            self.run_demo()

        self.assertFalse(self.output.exists())

    def test_blank_host_mappings_are_rejected(self):
        self.mappings.write_text(
            "  \n\n",
            encoding="utf-8",
        )

        with self.assertRaises(ValueError):
            self.run_demo()

        self.assertFalse(self.output.exists())


    def test_non_object_jsonl_is_rejected(self):
        self.events.write_text("[]\n", encoding="utf-8")

        with self.assertRaises(ValueError):
            self.run_demo()

        self.assertFalse(self.output.exists())

    def test_invalid_utf8_is_rejected(self):
        self.events.write_bytes(b"\xff\n")

        with self.assertRaises(ValueError):
            self.run_demo()

        self.assertFalse(self.output.exists())

    def test_conflicting_event_ids_are_rejected(self):
        lines = self.events.read_text(
            encoding="utf-8"
        ).splitlines()

        duplicate = json.loads(lines[0])
        duplicate["details"]["proto"] = "tcp"

        lines.append(json.dumps(duplicate, sort_keys=True))

        self.events.write_text(
            "\n".join(lines) + "\n",
            encoding="utf-8",
        )

        with self.assertRaises(ValueError):
            self.run_demo()

        self.assertFalse(self.output.exists())

    def test_conflicting_host_mappings_are_rejected(self):
        lines = self.mappings.read_text(
            encoding="utf-8"
        ).splitlines()

        duplicate = json.loads(lines[0])
        duplicate["ip"] = "192.0.2.254"

        lines.append(json.dumps(duplicate, sort_keys=True))

        self.mappings.write_text(
            "\n".join(lines) + "\n",
            encoding="utf-8",
        )

        with self.assertRaises(ValueError):
            self.run_demo()

        self.assertFalse(self.output.exists())

    def test_negative_window_is_rejected(self):
        with self.assertRaises(ValueError):
            run_demo(
                self.events,
                self.mappings,
                self.output,
                window_seconds=-1,
            )

        self.assertFalse(self.output.exists())

    def test_nan_window_is_rejected(self):
        with self.assertRaises(ValueError):
            run_demo(
                self.events,
                self.mappings,
                self.output,
                window_seconds=float("nan"),
            )

        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
