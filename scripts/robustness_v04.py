"""Evaluate detection robustness under controlled telemetry degradation."""

import argparse
import copy
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from benchmark_v04 import (
    verify_dataset,
    baseline_a,
    baseline_b,
    PROTECTED_NET,
    UNTRUSTED_NET,
)
from log_analyzer.correlation import correlate_events
from log_analyzer.detection import detect


CONDITIONS = (
    "original",
    "missing_connection",
    "missing_ntlm",
    "missing_notice",
    "uid_mismatch",
    "timestamp_skew",
    "reversed_input",
)

METHODS = ("baseline_a", "baseline_b", "r001")


def perturb(original_events, condition):
    events = copy.deepcopy(original_events)

    if condition == "missing_connection":
        return [
            e for e in events
            if e["event_type"] != "zeek.conn"
        ]

    if condition == "missing_ntlm":
        return [
            e for e in events
            if e["event_type"] != "zeek.ntlm"
        ]

    if condition == "missing_notice":
        return [
            e for e in events
            if e["event_type"] != "zeek.notice"
        ]

    if condition == "uid_mismatch":
        for event in events:
            if event["event_type"] == "zeek.ntlm":
                event["uid"] = event["uid"] + "-ALTERED"

    if condition == "timestamp_skew":
        for event in events:
            if event["event_type"] == "zeek.ntlm":
                timestamp = datetime.fromisoformat(
                    event["timestamp_utc"].replace(
                        "Z", "+00:00"
                    )
                )

                timestamp -= timedelta(seconds=60)

                event["timestamp_utc"] = (
                    timestamp.isoformat().replace(
                        "+00:00", "Z"
                    )
                )

    if condition == "reversed_input":
        events.reverse()

    return events


def evaluate(events):
    correlation = correlate_events(events)

    finding_report = detect(
        correlation,
        PROTECTED_NET,
        UNTRUSTED_NET,
    )

    return {
        "baseline_a": int(baseline_a(events)),
        "baseline_b": int(baseline_b(events)),
        "r001": int(bool(finding_report["findings"])),
    }


def run(dataset):
    manifest, events, labels = verify_dataset(dataset)

    grouped = defaultdict(list)

    for event in events:
        grouped[event["case_id"]].append(event)

    positive_cases = [
        label for label in labels
        if label["behavior_label"] == 1
    ]

    if not positive_cases:
        raise ValueError("Dataset has no positive cases")

    results = []
    summary = {}

    for condition in CONDITIONS:
        detected = {
            method: 0 for method in METHODS
        }

        for label in positive_cases:
            case_id = label["case_id"]

            modified = perturb(
                grouped[case_id],
                condition,
            )

            predictions = evaluate(modified)

            for method in METHODS:
                detected[method] += predictions[method]

            results.append({
                "case_id": case_id,
                "scenario_id": label["scenario_id"],
                "intent_annotation": label["intent_annotation"],
                "condition": condition,
                "observed_event_count": len(modified),
                "predictions": predictions,
            })

        summary[condition] = {
            method: {
                "detected": detected[method],
                "total": len(positive_cases),
                "recall": round(
                    detected[method] / len(positive_cases),
                    6,
                ),
            }
            for method in METHODS
        }

    return {
        "experiment": "v0.4_telemetry_robustness",
        "dataset_type": manifest["dataset_type"],
        "positive_cases": len(positive_cases),
        "conditions": list(CONDITIONS),
        "label_interpretation": (
            "Ground truth describes the underlying "
            "scenario before telemetry perturbation."
        ),
        "summary": summary,
        "case_results": results,
        "limitations": [
            "Only synthetic positive cases are tested.",
            "Results measure recall, not precision.",
            "Perturbations are deterministic and artificial.",
            "This is not production detection performance.",
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
        default=ROOT / "results/robustness-v0.4.json",
    )

    args = parser.parse_args()

    try:
        report = run(args.dataset)

        args.output.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        args.output.write_text(
            json.dumps(report, indent=2) + "\n",
            encoding="utf-8",
        )

        print(json.dumps(report["summary"], indent=2))

    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()