"""TDD contract for reproducible V0.9 research evidence."""

import hashlib
import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from export_comparison_v09 import export_evidence


FILES = {
    "events.jsonl",
    "labels.jsonl",
    "host-mappings.jsonl",
    "benchmark-results.json",
    "manifest.json",
}


class TestComparisonExportV09(unittest.TestCase):

    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / "v09"

    def export(self, **kwargs):
        return export_evidence(self.output, **kwargs)

    def read_json(self, name):
        return json.loads(
            (self.output / name).read_text(encoding="utf-8")
        )

    def read_jsonl(self, name):
        return [
            json.loads(line)
            for line in (
                self.output / name
            ).read_text(encoding="utf-8").splitlines()
        ]

    def test_exactly_five_evidence_files(self):
        self.export()
        self.assertEqual(
            {p.name for p in self.output.iterdir()},
            FILES,
        )

    def test_manifest_and_provenance(self):
        manifest = self.export()
        self.assertEqual(manifest, self.read_json("manifest.json"))
        self.assertEqual(manifest["dataset_version"], "v0.9")
        self.assertEqual(manifest["seed"], 20261011)
        self.assertEqual(manifest["repeats"], 1)
        self.assertEqual(manifest["event_count"], 32)
        self.assertEqual(manifest["label_count"], 16)
        self.assertEqual(manifest["host_mapping_count"], 16)
        self.assertEqual(manifest["positive_count"], 8)
        self.assertEqual(manifest["negative_count"], 8)
        self.assertEqual(manifest["evaluation_window_seconds"], 120)
        self.assertIs(manifest["production_accuracy_claim"], False)
        self.assertEqual(
            manifest["reproduction"],
            {
                "generator": "scripts/generate_comparison_v09.py",
                "evaluator": "scripts/evaluate_comparison_v09.py",
                "exporter": "scripts/export_comparison_v09.py",
            },
        )

    def test_hashes_utf8_and_lf(self):
        manifest = self.export()
        self.assertEqual(
            set(manifest["files"]),
            FILES - {"manifest.json"},
        )

        for name in FILES:
            with self.subTest(file=name):
                data = (self.output / name).read_bytes()
                self.assertTrue(data.endswith(b"\n"))
                self.assertNotIn(b"\r", data)
                self.assertFalse(data.startswith(b"\xef\xbb\xbf"))
                data.decode("utf-8", errors="strict")

                if name != "manifest.json":
                    self.assertEqual(
                        hashlib.sha256(data).hexdigest(),
                        manifest["files"][name]["sha256"],
                    )

    def test_record_counts_and_label_separation(self):
        manifest = self.export()
        expected = {
            "events.jsonl": 32,
            "labels.jsonl": 16,
            "host-mappings.jsonl": 16,
        }

        for name, count in expected.items():
            self.assertEqual(len(self.read_jsonl(name)), count)
            self.assertEqual(
                manifest["files"][name]["records"], count
            )

        for name in ("events.jsonl", "host-mappings.jsonl"):
            for record in self.read_jsonl(name):
                for forbidden in ("related", "scenario", "case_id"):
                    self.assertNotIn(forbidden, record)

    def test_three_method_results(self):
        self.export()
        result = self.read_json("benchmark-results.json")
        expected = {
            "time_only": (7, 8, 0, 1),
            "ip_time": (6, 6, 2, 2),
            "v08_policy": (5, 1, 7, 3),
        }

        self.assertEqual(result["label_count"], 16)
        self.assertIs(result["production_accuracy_claim"], False)

        for name, values in expected.items():
            counts = result["methods"][name]["counts"]
            actual = tuple(
                counts[key] for key in ("tp", "fp", "tn", "fn")
            )
            self.assertEqual(actual, values)

    def test_byte_identical_regeneration(self):
        self.export()
        second = Path(self.temp.name) / "second"
        export_evidence(second)

        for name in FILES:
            with self.subTest(file=name):
                self.assertEqual(
                    (self.output / name).read_bytes(),
                    (second / name).read_bytes(),
                )

    def test_121_second_window(self):
        self.export(window_seconds=121)
        result = self.read_json("benchmark-results.json")
        self.assertEqual(result["window_seconds"], 121)
        self.assertEqual(
            result["methods"]["v08_policy"]["counts"],
            {"tp": 6, "fp": 1, "tn": 7, "fn": 2},
        )

    def test_repeated_dataset(self):
        manifest = self.export(repeats=2)
        result = self.read_json("benchmark-results.json")

        self.assertEqual(manifest["event_count"], 64)
        self.assertEqual(manifest["label_count"], 32)
        self.assertEqual(manifest["host_mapping_count"], 32)
        self.assertEqual(
            result["methods"]["v08_policy"]["counts"],
            {"tp": 10, "fp": 2, "tn": 14, "fn": 6},
        )


if __name__ == "__main__":
    unittest.main()
