"""Evaluate security detection methods using labelled synthetic cases."""

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from log_analyzer.correlation import correlate_events
from log_analyzer.detection import detect


PROTECTED_NET = "10.10.20.0/24"
UNTRUSTED_NET = "10.10.30.0/24"

METHODS = (
    "baseline_a_tcp445",
    "baseline_b_ntlm",
    "r001_correlated",
)


def load_jsonl(path):
    records = []

    with path.open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"{path.name}:{line_number}: invalid JSON"
                ) from exc

            if not isinstance(record, dict):
                raise ValueError(
                    f"{path.name}:{line_number}: expected object"
                )

            records.append(record)

    return records


def verify_dataset(directory):
    manifest_path = directory / "manifest.json"
    manifest = json.loads(
        manifest_path.read_text(encoding="utf-8")
    )

    for filename in ("events.jsonl", "labels.jsonl"):
        path = directory / filename
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        expected = manifest["sha256"][filename]

        if actual != expected:
            raise ValueError(
                f"SHA256 verification failed: {filename}"
            )

    events = load_jsonl(directory / "events.jsonl")
    labels = load_jsonl(directory / "labels.jsonl")

    if len(events) != manifest["events"]:
        raise ValueError("Event count mismatch")

    if len(labels) != manifest["cases"]:
        raise ValueError("Case count mismatch")

    if len({row["case_id"] for row in labels}) != len(labels):
        raise ValueError("Duplicate case IDs in labels")

    label_ids = {row["case_id"] for row in labels}

    if any(row.get("case_id") not in label_ids for row in events):
        raise ValueError("Event references unknown case ID")

    for row in labels:
        if (
            type(row.get("behavior_label")) is not int
            or row["behavior_label"] not in (0, 1)
        ):
            raise ValueError("Invalid behavior label")

    positive = sum(row["behavior_label"] for row in labels)

    if positive != manifest["behavior_positive"]:
        raise ValueError("Positive-label count mismatch")

    if len(labels) - positive != manifest["behavior_negative"]:
        raise ValueError("Negative-label count mismatch")

    return manifest, events, labels


def baseline_a(events):
    """Detect any TCP/445 connection record."""
    return any(
        event.get("event_type") == "zeek.conn"
        and isinstance(event.get("destination"), dict)
        and event["destination"].get("port") == 445
        for event in events
    )


def baseline_b(events):
    """Detect any parsed NTLM event."""
    return any(
        event.get("event_type") == "zeek.ntlm"
        for event in events
    )


def evaluate_metrics(rows, method):
    tp = fp = tn = fn = 0

    for row in rows:
        truth = row["behavior_label"]
        prediction = row["predictions"][method]

        if truth == 1 and prediction == 1:
            tp += 1
        elif truth == 0 and prediction == 1:
            fp += 1
        elif truth == 0 and prediction == 0:
            tn += 1
        elif truth == 1 and prediction == 0:
            fn += 1

    def ratio(numerator, denominator):
        return (
            round(numerator / denominator, 6)
            if denominator else None
        )

    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)

    if precision is None or recall is None:
        f1 = None
    elif precision + recall == 0:
        f1 = 0.0
    else:
        f1 = round(
            2 * precision * recall / (precision + recall),
            6,
        )

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_positive_rate": ratio(fp, fp + tn),
        "accuracy": ratio(tp + tn, len(rows)),
    }


def run_benchmark(directory):
    manifest, events, labels = verify_dataset(directory)

    events_by_case = defaultdict(list)

    for event in events:
        events_by_case[event["case_id"]].append(event)

    results = []

    for label in labels:
        case_id = label["case_id"]
        case_events = events_by_case[case_id]

        correlation = correlate_events(case_events)

        detection = detect(
            correlation,
            PROTECTED_NET,
            UNTRUSTED_NET,
        )

        predictions = {
            "baseline_a_tcp445": int(
                baseline_a(case_events)
            ),
            "baseline_b_ntlm": int(
                baseline_b(case_events)
            ),
            "r001_correlated": int(
                bool(detection["findings"])
            ),
        }

        results.append({
            "case_id": case_id,
            "scenario_id": label["scenario_id"],
            "behavior_label": label["behavior_label"],
            "intent_annotation": label["intent_annotation"],
            "event_count": len(case_events),
            "predictions": predictions,
            "r001_finding_uids": [
                finding["uid"]
                for finding in detection["findings"]
            ],
        })

    metrics = {
        method: evaluate_metrics(results, method)
        for method in METHODS
    }

    errors = {
        method: [
            {
                "case_id": row["case_id"],
                "scenario_id": row["scenario_id"],
                "expected": row["behavior_label"],
                "predicted": row["predictions"][method],
            }
            for row in results
            if row["predictions"][method]
            != row["behavior_label"]
        ]
        for method in METHODS
    }

    authorized_flagged = sum(
        row["intent_annotation"] == "authorized"
        and row["predictions"]["r001_correlated"] == 1
        for row in results
    )

    return {
        "benchmark_version": "0.4.0",
        "dataset_type": "synthetic",
        "dataset_manifest": manifest,
        "evaluation_target": "observable_behavior",
        "case_count": len(results),
        "scenario_counts": dict(
            sorted(Counter(
                row["scenario_id"] for row in results
            ).items())
        ),
        "metrics": metrics,
        "authorized_cases_flagged_by_r001": authorized_flagged,
        "errors": errors,
        "case_results": results,
        "limitations": [
            "Labels refer to observable behavior, not malicious intent.",
            "Synthetic tests do not establish production accuracy.",
            "Rules and synthetic scenarios share predefined assumptions.",
            "Authorized authentication can still match the R001 rule.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        type=Path,
        default=ROOT / "datasets/synthetic/v0.4",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "results/benchmark-v0.4.json",
    )

    args = parser.parse_args()

    try:
        report = run_benchmark(args.dataset)

        args.output.parent.mkdir(
            parents=True, exist_ok=True
        )

        args.output.write_text(
            json.dumps(report, indent=2) + "\n",
            encoding="utf-8",
        )

        print(json.dumps({
            "cases": report["case_count"],
            "metrics": report["metrics"],
            "authorized_cases_flagged_by_r001":
                report["authorized_cases_flagged_by_r001"],
        }, indent=2))

    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()