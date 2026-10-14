
"""V0.8 reproducible synthetic evidence export contract.

All relationship labels describe synthetic activities, not attacks.
"""

import hashlib
import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from export_three_source_v08 import export_evidence


FILES = {
    "events.jsonl",
    "labels.jsonl",
    "host-mappings.jsonl",
    "benchmark-results.json",
    "manifest.json",
}


class TestThreeSourceExportV08(unittest.TestCase):

    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / "evidence"

    def export(self, **kwargs):
        return export_evidence(self.output, **kwargs)

    def read_json(self, name):
        return json.loads(
            (self.output / name).read_text(encoding="utf-8")
        )

    def read_jsonl(self, name):
        text = (self.output / name).read_text(
            encoding="utf-8"
        )
        return [
            json.loads(line)
            for line in text.splitlines()
        ]

    def test_expected_five_files(self):
        self.export()

        self.assertEqual(
            {p.name for p in self.output.iterdir()},
            FILES,
        )

    def test_manifest_metadata_and_reproduction_paths(self):
        manifest = self.export()

        self.assertEqual(
            manifest, self.read_json("manifest.json")
        )
        self.assertEqual(
            manifest["dataset_version"], "v0.8-phase2"
        )
        self.assertEqual(
            manifest["schema_version"], "0.7.0"
        )
        self.assertEqual(manifest["seed"], 20261011)
        self.assertEqual(manifest["repeats"], 1)
        self.assertEqual(
            manifest["evaluation_window_seconds"], 120
        )
        self.assertEqual(manifest["event_count"], 12)
        self.assertEqual(manifest["label_count"], 6)
        self.assertEqual(
            manifest["host_mapping_count"], 6
        )
        self.assertIs(
            manifest["production_accuracy_claim"], False
        )
        self.assertEqual(
            set(manifest["reproduction"]),
            {"generator", "evaluator", "exporter"},
        )

    def test_all_file_digests_match_exact_bytes(self):
        manifest = self.export()

        self.assertEqual(
            set(manifest["files"]),
            FILES - {"manifest.json"},
        )

        for name, info in manifest["files"].items():
            with self.subTest(name=name):
                data = (self.output / name).read_bytes()

                self.assertEqual(
                    hashlib.sha256(data).hexdigest(),
                    info["sha256"],
                )
                self.assertEqual(
                    len(info["sha256"]), 64
                )

    def test_utf8_lf_line_endings(self):
        self.export()

        for name in FILES:
            with self.subTest(name=name):
                data = (self.output / name).read_bytes()

                self.assertTrue(data.endswith(b"\n"))
                self.assertNotIn(b"\r", data)
                data.decode("utf-8", errors="strict")

    def test_jsonl_counts_and_manifest_record_totals(self):
        manifest = self.export()

        for name, count in (
            ("events.jsonl", 12),
            ("labels.jsonl", 6),
            ("host-mappings.jsonl", 6),
        ):
            with self.subTest(name=name):
                self.assertEqual(
                    len(self.read_jsonl(name)), count
                )
                self.assertEqual(
                    manifest["files"][name]["records"],
                    count,
                )

    def test_evaluation_results_and_scope(self):
        self.export()
        result = self.read_json("benchmark-results.json")

        self.assertEqual(
            result["counts"],
            {"tp": 3, "fp": 1, "tn": 2, "fn": 0},
        )
        self.assertEqual(
            result["candidate_pair_count"], 4
        )
        self.assertAlmostEqual(
            result["metrics"]["precision"], 0.75
        )
        self.assertAlmostEqual(
            result["metrics"]["recall"], 1.0
        )
        self.assertAlmostEqual(
            result["metrics"]["f1"], 6 / 7
        )
        self.assertIs(
            result["production_accuracy_claim"], False
        )

    def test_nat_false_association_is_preserved(self):
        self.export()
        result = self.read_json("benchmark-results.json")

        cases = {
            case["scenario"]: case
            for case in result["cases"]
        }
        nat = cases["N01_nat_collision"]

        self.assertEqual(nat["classification"], "FP")
        self.assertIs(nat["related"], False)
        self.assertIs(nat["predicted"], True)

    def test_labels_do_not_leak_into_observations(self):
        self.export()

        forbidden = {
            "related", "ground_truth",
            "scenario", "case_id",
        }

        for name in (
            "events.jsonl",
            "host-mappings.jsonl",
        ):
            for record in self.read_jsonl(name):
                self.assertTrue(
                    forbidden.isdisjoint(record)
                )

                details = record.get("details")
                if isinstance(details, dict):
                    self.assertTrue(
                        forbidden.isdisjoint(details)
                    )

    def test_byte_identical_across_output_directories(self):
        self.export()

        other_dir = Path(self.temp.name) / "second"
        export_evidence(other_dir)

        for name in FILES:
            with self.subTest(name=name):
                self.assertEqual(
                    (self.output / name).read_bytes(),
                    (other_dir / name).read_bytes(),
                )

    def test_repeated_dataset_scales_evidence(self):
        manifest = self.export(repeats=2)
        result = self.read_json("benchmark-results.json")

        self.assertEqual(manifest["event_count"], 24)
        self.assertEqual(manifest["label_count"], 12)
        self.assertEqual(
            manifest["host_mapping_count"], 12
        )
        self.assertEqual(
            result["counts"],
            {"tp": 6, "fp": 2, "tn": 4, "fn": 0},
        )


if __name__ == "__main__":
    unittest.main()
