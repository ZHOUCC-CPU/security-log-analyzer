"""Evaluate the impact of synthetic telemetry faults on R001."""

import argparse
import copy
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from benchmark_v04 import (
    verify_dataset,
    PROTECTED_NET,
    UNTRUSTED_NET,
)
from log_analyzer.correlation import correlate_events
from log_analyzer.detection import detect
from log_analyzer.quality import assess_event_quality


CONDITIONS = (
    "original",
    "duplicate_ntlm",
    "missing_ntlm_uid",
    "missing_ntlm_source_ip",
    "invalid_ntlm_source_ip",
    "invalid_ntlm_timestamp",
    "drop_ntlm",
    "timestamp_skew_back_60s",
)


def inject_fault(original_events, condition):
    """Apply one controlled fault without changing the original."""

    events = copy.deepcopy(original_events)

    if condition == "original":
        return events

    ntlm = next(
        (event for event in events
         if event["event_type"] == "zeek.ntlm"),
        None,
    )

    if ntlm is None:
        raise ValueError("Scenario has no NTLM event")

    if condition == "duplicate_ntlm":
        events.append(copy.deepcopy(ntlm))

    elif condition == "missing_ntlm_uid":
        ntlm["uid"] = None

    elif condition == "missing_ntlm_source_ip":
        ntlm["source"]["ip"] = None

    elif condition == "invalid_ntlm_source_ip":
        ntlm["source"]["ip"] = "999.999.999.999"

    elif condition == "invalid_ntlm_timestamp":
        ntlm["timestamp_utc"] = "invalid-timestamp"

    elif condition == "drop_ntlm":
        events = [
            event for event in events
            if event["event_type"] != "zeek.ntlm"
        ]

    elif condition == "timestamp_skew_back_60s":
        timestamp = datetime.fromisoformat(
            ntlm["timestamp_utc"].replace("Z", "+00:00")
        )
        timestamp -= timedelta(seconds=60)
        ntlm["timestamp_utc"] = (
            timestamp.isoformat().replace("+00:00", "Z")
        )

    else:
        raise ValueError(f"Unknown condition: {condition}")

    return events


def evaluate_case(events):
    """Keep processing errors separate from negative decisions."""

    try:
        correlation = correlate_events(events)
        detection = detect(
            correlation,
            PROTECTED_NET,
            UNTRUSTED_NET,
        )

        return {
            "alert": bool(detection["findings"]),
            "processing_error": None,
        }

    except (ValueError, TypeError, KeyError, OverflowError) as exc:
        return {
            "alert": None,
            "processing_error": (
                f"{type(exc).__name__}: {exc}"
            ),
        }


def run_experiment(dataset):
    manifest, events, labels = verify_dataset(dataset)

    grouped = defaultdict(list)

    for event in events:
        grouped[event["case_id"]].append(event)

    positives = [
        label for label in labels
        if label["behavior_label"] == 1
    ]

    if not positives:
        raise ValueError("No behavior-positive cases")

    summaries = {}
    case_results = []

    for condition in CONDITIONS:
        counters = Counter()
        issue_totals = Counter()

        for label in positives:
            case_id = label["case_id"]

            modified = inject_fault(
                grouped[case_id],
                condition,
            )

            quality = assess_event_quality(modified)
            outcome = evaluate_case(modified)

            issue_totals.update(quality["issue_counts"])

            counters["cases"] += 1

            if quality["summary"]["records_with_issues"] > 0:
                counters["quality_flagged_cases"] += 1

            if outcome["processing_error"] is not None:
                counters["processing_errors"] += 1

            elif outcome["alert"] is True:
                counters["r001_alerts"] += 1

            else:
                counters["no_r001_alert"] += 1

            case_results.append({
                "case_id": case_id,
                "scenario_id": label["scenario_id"],
                "condition": condition,
                "original_behavior_label": 1,
                "intent_annotation": label["intent_annotation"],
                "observed_event_count": len(modified),
                "quality_issues": quality["issue_counts"],
                "r001_alert": outcome["alert"],
                "processing_error": outcome["processing_error"],
            })

        processed = (
            counters["cases"] - counters["processing_errors"]
        )

        summaries[condition] = {
            "cases": counters["cases"],
            "quality_flagged_cases": counters[
                "quality_flagged_cases"
            ],
            "r001_alerts": counters["r001_alerts"],
            "no_r001_alert": counters["no_r001_alert"],
            "processing_errors": counters["processing_errors"],
            "alert_fraction_of_all_cases": round(
                counters["r001_alerts"] / counters["cases"], 6
            ),
            "alert_fraction_of_processed_cases": (
                round(counters["r001_alerts"] / processed, 6)
                if processed else None
            ),
            "issue_counts": dict(sorted(issue_totals.items())),
        }

    return {
        "experiment": "v0.6_quality_impact",
        "dataset_type": manifest["dataset_type"],
        "original_positive_cases": len(positives),
        "conditions": list(CONDITIONS),
        "total_case_condition_runs": len(case_results),
        "summary": summaries,
        "case_results": case_results,
        "limitations": [
            "Only original behavior-positive cases are evaluated.",
            "This experiment does not measure false positives.",
            "A processing error is not a negative prediction.",
            "Dropped records cannot be inferred from remaining data alone.",
            "Timestamp skew can be syntactically valid.",
            "Synthetic results do not establish production accuracy.",
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
        default=ROOT / "results/quality-impact-v0.6.json",
    )

    args = parser.parse_args()

    try:
        report = run_experiment(args.dataset)

        args.output.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        args.output.write_text(
            json.dumps(report, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )

        print(json.dumps({
            "original_positive_cases":
                report["original_positive_cases"],
            "total_case_condition_runs":
                report["total_case_condition_runs"],
            "summary": report["summary"],
        }, indent=2))

    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()