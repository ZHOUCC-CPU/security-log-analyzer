"""Export deterministic V0.8 phase-two synthetic evidence.

Synthetic labels describe simulated activities, not attacks.
All files use UTF-8 and LF line endings.
"""

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from generate_three_source_v08 import generate_dataset
from evaluate_three_source_v08 import evaluate_dataset


DEFAULT_SEED = 20261011
DEFAULT_REPEATS = 1
DEFAULT_WINDOW_SECONDS = 120
OUTPUT = ROOT / "docs" / "evidence" / "v0.8"


def _json_bytes(value):
    text = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
        allow_nan=False,
    )
    return (text + "\n").encode("utf-8")


def _jsonl_bytes(records):
    lines = [
        json.dumps(
            record,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        for record in records
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def export_evidence(
    output_dir,
    *,
    repeats=DEFAULT_REPEATS,
    seed=DEFAULT_SEED,
    window_seconds=DEFAULT_WINDOW_SECONDS,
):
    """Export evidence and return the verification manifest."""

    dataset = generate_dataset(
        repeats=repeats,
        seed=seed,
    )

    result = evaluate_dataset(
        dataset,
        window_seconds=window_seconds,
    )

    payloads = {
        "events.jsonl": _jsonl_bytes(dataset["events"]),
        "labels.jsonl": _jsonl_bytes(dataset["labels"]),
        "host-mappings.jsonl": _jsonl_bytes(
            dataset["host_mappings"]
        ),
        "benchmark-results.json": _json_bytes(result),
    }

    record_counts = {
        "events.jsonl": len(dataset["events"]),
        "labels.jsonl": len(dataset["labels"]),
        "host-mappings.jsonl": len(dataset["host_mappings"]),
    }

    files = {}

    for name, data in payloads.items():
        info = {
            "sha256": hashlib.sha256(data).hexdigest()
        }

        if name in record_counts:
            info["records"] = record_counts[name]

        files[name] = info

    manifest = {
        **dataset["manifest"],
        "evaluation_window_seconds": window_seconds,
        "evaluation_scope": (
            "predefined_synthetic_activity_relationship"
        ),
        "production_accuracy_claim": False,
        "files": files,
        "reproduction": {
            "generator": "scripts/generate_three_source_v08.py",
            "evaluator": "scripts/evaluate_three_source_v08.py",
            "exporter": "scripts/export_three_source_v08.py",
        },
    }

    payloads["manifest.json"] = _json_bytes(manifest)

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)

    for name, data in payloads.items():
        (destination / name).write_bytes(data)

    return manifest


if __name__ == "__main__":
    manifest = export_evidence(OUTPUT)

    print("[PASS] V0.8 synthetic evidence exported")
    print("Output:", OUTPUT)
    print("Events:", manifest["event_count"])
    print("Labels:", manifest["label_count"])
    print("Host mappings:", manifest["host_mapping_count"])
