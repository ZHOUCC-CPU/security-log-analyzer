
"""Evaluate synthetic negative cases under controlled telemetry faults."""

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from benchmark_v04 import verify_dataset
from quality_impact_v06 import (
    CONDITIONS,
    inject_fault,
    evaluate_case,
)
from log_analyzer.quality import assess_event_quality


def run_negative_experiment(dataset):
    manifest, events, labels = verify_dataset(dataset)

    grouped = defaultdict(list)
    for event in events:
        grouped[event["case_id"]].append(event)

    negatives = [
        label for label in labels
        if label["behavior_label"] == 0
    ]

    if not negatives:
        raise ValueError("No behavior-negative cases")

    baseline = {
        label["case_id"]: evaluate_case(
            grouped[label["case_id"]]
        )
        for label in negatives
    }

    summaries = {}
    case_results = []

    for condition in CONDITIONS:
        counts = Counter()
        issue_totals = Counter()

        for label in negatives:
            case_id = label["case_id"]
            original = grouped[case_id]

            has_ntlm = any(
                event["event_type"] == "zeek.ntlm"
                for event in original
            )

            counts["cases"] += 1

            if condition != "original" and not has_ntlm:
                counts["not_applicable"] += 1

                case_results.append({
                    "case_id": case_id,
                    "scenario_id": label["scenario_id"],
                    "condition": condition,
                    "status": "not_applicable",
                    "reason": "No original NTLM record",
                    "r001_alert": None,
                    "processing_error": None,
                })
                continue

            modified = inject_fault(
                original,
                condition,
            )

            quality = assess_event_quality(modified)
            outcome = evaluate_case(modified)

            counts["evaluated"] += 1
            issue_totals.update(quality["issue_counts"])

            if quality["summary"]["records_with_issues"]:
                counts["quality_flagged_cases"] += 1

            if outcome["processing_error"] is not None:
                counts["processing_errors"] += 1
            elif outcome["alert"] is True:
                counts["r001_alerts"] += 1
            else:
                counts["no_r001_alert"] += 1

            new_alert = (
                baseline[case_id]["processing_error"] is None
                and baseline[case_id]["alert"] is False
                and outcome["processing_error"] is None
                and outcome["alert"] is True
            )

            if new_alert:
                counts["new_alerts_vs_original"] += 1

            case_results.append({
                "case_id": case_id,
                "scenario_id": label["scenario_id"],
                "condition": condition,
                "status": "evaluated",
                "intent_annotation": label["intent_annotation"],
                "observed_event_count": len(modified),
                "quality_issues": quality["issue_counts"],
                "baseline_r001_alert": baseline[case_id]["alert"],
                "r001_alert": outcome["alert"],
                "new_alert_vs_original": new_alert,
                "processing_error": outcome["processing_error"],
            })

        evaluated = counts["evaluated"]
        accounted = (
            counts["r001_alerts"]
            + counts["no_r001_alert"]
            + counts["processing_errors"]
        )

        if accounted != evaluated:
            raise AssertionError(
                f"Outcome accounting failed: {condition}"
            )

        if evaluated + counts["not_applicable"] != len(negatives):
            raise AssertionError(
                f"Coverage accounting failed: {condition}"
            )

        summaries[condition] = {
            "cases": counts["cases"],
            "evaluated": evaluated,
            "not_applicable": counts["not_applicable"],
            "quality_flagged_cases": counts[
                "quality_flagged_cases"
            ],
            "r001_alerts": counts["r001_alerts"],
            "no_r001_alert": counts["no_r001_alert"],
            "processing_errors": counts["processing_errors"],
            "new_alerts_vs_original": counts[
                "new_alerts_vs_original"
            ],
            "issue_counts": dict(sorted(issue_totals.items())),
        }

    return {
        "experiment": "v0.6_negative_quality_impact",
        "dataset_type": manifest["dataset_type"],
        "original_negative_cases": len(negatives),
        "conditions": list(CONDITIONS),
        "total_case_condition_slots": len(case_results),
        "summary": summaries,
        "case_results": case_results,
        "limitations": [
            "Negative labels represent predefined observable behavior.",
            "A new alert is not proof of a real-world false positive.",
            "Conditions requiring NTLM are not applicable without NTLM.",
            "Processing errors are not treated as negative decisions.",
            "Injected faults are synthetic and controlled.",
            "Results do not establish production detection accuracy.",
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
        default=ROOT / "results/quality-negative-v0.6.json",
    )

    args = parser.parse_args()

    try:
        report = run_negative_experiment(args.dataset)

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
            "original_negative_cases":
                report["original_negative_cases"],
            "total_case_condition_slots":
                report["total_case_condition_slots"],
            "summary": report["summary"],
        }, indent=2))

    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
