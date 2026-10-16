"""Export reproducible V0.9 synthetic association evidence.

Labels represent simulated relationships, not confirmed attacks.
Output uses deterministic UTF-8 serialization and LF newlines.
"""

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from generate_comparison_v09 import generate_expanded_dataset
from evaluate_comparison_v09 import evaluate_comparison


OUTPUT = ROOT / "docs" / "evidence" / "v0.9"
DEFAULT_SEED = 20261011
DEFAULT_REPEATS = 1
DEFAULT_WINDOW_SECONDS = 120


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
    """Export deterministic evidence and return its manifest."""

    destination = Path(output_dir).resolve()

    # Protect previously archived research evidence.
    for version in ("v0.7", "v0.8"):
        protected = (
            ROOT / "docs" / "evidence" / version
        ).resolve()

        if destination == protected or protected in destination.parents:
            raise ValueError(
                "Refusing to overwrite archived " + version + " evidence"
            )

    dataset = generate_expanded_dataset(
        repeats=repeats,
        seed=seed,
    )

    result = evaluate_comparison(
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

    file_metadata = {}

    for name, data in payloads.items():
        metadata = {
            "sha256": hashlib.sha256(data).hexdigest()
        }

        if name in record_counts:
            metadata["records"] = record_counts[name]

        file_metadata[name] = metadata

    manifest = {
        **dataset["manifest"],
        "evaluation_window_seconds": window_seconds,
        "evaluation_scope": (
            "predefined_synthetic_activity_relationship"
        ),
        "production_accuracy_claim": False,
        "files": file_metadata,
        "reproduction": {
            "generator": "scripts/generate_comparison_v09.py",
            "evaluator": "scripts/evaluate_comparison_v09.py",
            "exporter": "scripts/export_comparison_v09.py",
        },
    }

    # The manifest records hashes of data files.
    # It deliberately does not contain its own hash.
    payloads["manifest.json"] = _json_bytes(manifest)

    if destination.exists() and not destination.is_dir():
        raise ValueError("Output path is not a directory")

    destination.mkdir(parents=True, exist_ok=True)

    for name, data in payloads.items():
        (destination / name).write_bytes(data)

    return manifest


if __name__ == "__main__":
    manifest = export_evidence(OUTPUT)

    print("[PASS] V0.9 synthetic evidence exported")
    print("Output:", OUTPUT)
    print("Events:", manifest["event_count"])
    print("Labels:", manifest["label_count"])
    print("Host mappings:", manifest["host_mapping_count"])
    print("Evaluation window:", manifest["evaluation_window_seconds"])
