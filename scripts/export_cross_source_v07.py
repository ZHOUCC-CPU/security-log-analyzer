
"""Export reproducible V0.7 cross-source benchmark evidence.

All records are synthetic. Ground-truth labels represent
predefined activity relationships, not confirmed attacks.

UTF-8 output uses LF line endings on every platform.
"""

import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from generate_cross_source_v07 import generate_dataset
from evaluate_cross_source_v07 import evaluate_dataset


SEED = 20261010
REPEATS = 1
WINDOW_SECONDS = 120

OUTPUT = ROOT / "docs" / "evidence" / "v0.7"


def json_bytes(value):
    """Serialize deterministically using UTF-8 and LF."""

    text = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
        allow_nan=False,
    )

    return (text + "\n").encode("utf-8")


def jsonl_bytes(records):
    """Serialize one JSON object per line."""

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


def save_bytes(name, data):
    """Save evidence and return its SHA-256 hash."""

    path = OUTPUT / name
    path.write_bytes(data)

    digest = hashlib.sha256(data).hexdigest()

    print(
        f"[SAVED] {name}: "
        f"{len(data)} bytes, SHA256={digest}"
    )

    return digest


def export():
    OUTPUT.mkdir(parents=True, exist_ok=True)

    dataset = generate_dataset(
        repeats=REPEATS,
        seed=SEED,
    )

    result = evaluate_dataset(
        dataset,
        window_seconds=WINDOW_SECONDS,
    )

    events_hash = save_bytes(
        "events.jsonl",
        jsonl_bytes(dataset["events"]),
    )

    labels_hash = save_bytes(
        "labels.jsonl",
        jsonl_bytes(dataset["labels"]),
    )

    results_hash = save_bytes(
        "benchmark-results.json",
        json_bytes(result),
    )

    manifest = {
        **dataset["manifest"],
        "evaluation_window_seconds": WINDOW_SECONDS,
        "evaluation_scope": (
            "predefined_synthetic_activity_relationship"
        ),
        "production_accuracy_claim": False,
        "files": {
            "events.jsonl": {
                "sha256": events_hash,
                "records": len(dataset["events"]),
            },
            "labels.jsonl": {
                "sha256": labels_hash,
                "records": len(dataset["labels"]),
            },
            "benchmark-results.json": {
                "sha256": results_hash,
            },
        },
        "reproduction": {
            "generator": (
                "scripts/generate_cross_source_v07.py"
            ),
            "evaluator": (
                "scripts/evaluate_cross_source_v07.py"
            ),
            "exporter": (
                "scripts/export_cross_source_v07.py"
            ),
        },
    }

    save_bytes(
        "manifest.json",
        json_bytes(manifest),
    )

    print("\n========== BENCHMARK ==========")
    print("Events:", len(dataset["events"]))
    print("Labels:", len(dataset["labels"]))
    print("Counts:", result["counts"])
    print("Metrics:", result["metrics"])
    print(
        "Candidate pairs:",
        result["candidate_pair_count"],
    )

    print("\n[PASS] V0.7 evidence exported")


if __name__ == "__main__":
    export()
