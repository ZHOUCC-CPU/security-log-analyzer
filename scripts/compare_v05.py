"""Compare V0.5 explained reports against V0.4 detection results."""

import argparse
import copy
import json
import sys
from collections import Counter, defaultdict
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
from log_analyzer.reporting import build_explained_report


LEVELS = (
    "corroborated",
    "partial",
    "conflicting",
    "no_relevant_evidence",
)


def compare(dataset, previous_report):
    manifest, events, labels = verify_dataset(dataset)

    previous = json.loads(
        previous_report.read_text(encoding="utf-8")
    )

    if previous["dataset_manifest"]["sha256"] != manifest["sha256"]:
        raise ValueError("V0.4 and V0.5 dataset hashes differ")

    old_rows = previous["case_results"]
    old_cases = {row["case_id"]: row for row in old_rows}

    if len(old_cases) != len(old_rows):
        raise ValueError("Duplicate V0.4 case IDs")

    if len(old_cases) != len(labels):
        raise ValueError("V0.4 case count differs")

    grouped = defaultdict(list)

    for event in events:
        grouped[event["case_id"]].append(event)

    level_counts = Counter()
    unalerted_counts = Counter()
    scenario_levels = defaultdict(Counter)

    case_results = []
    findings_total = 0
    unalerted_total = 0
    authorized_flagged = 0

    for label in labels:
        case_id = label["case_id"]

        if case_id not in old_cases:
            raise ValueError(f"Missing V0.4 case: {case_id}")

        old = old_cases[case_id]
        case_events = grouped[case_id]

        if (
            old["behavior_label"] != label["behavior_label"]
            or old["scenario_id"] != label["scenario_id"]
        ):
            raise ValueError(f"Label mismatch: {case_id}")

        correlation = correlate_events(case_events)

        detection = detect(
            correlation,
            PROTECTED_NET,
            UNTRUSTED_NET,
        )

        explained = build_explained_report(
            correlation,
            detection,
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

        if predictions != old["predictions"]:
            raise ValueError(
                f"Detection predictions changed: {case_id}"
            )

        # Remove only the added enrichment for comparison.
        restored_detection = copy.deepcopy(
            explained["detection_report"]
        )

        for finding in restored_detection["findings"]:
            finding.pop("evidence_assessment", None)

        if restored_detection != detection:
            raise ValueError(
                f"Original detection data changed: {case_id}"
            )

        old_uids = old["r001_finding_uids"]
        current_uids = [
            finding["uid"]
            for finding in detection["findings"]
        ]

        if old_uids != current_uids:
            raise ValueError(
                f"Finding UIDs changed: {case_id}"
            )

        assessments = explained[
            "evidence_report"
        ]["assessments"]

        unalerted = explained["unalerted_assessments"]

        if (
            len(assessments)
            != len(unalerted) + len(detection["findings"])
        ):
            raise ValueError(
                f"Evidence group accounting failed: {case_id}"
            )

        levels = Counter(
            item["evidence_level"]
            for item in assessments
        )

        level_counts.update(levels)
        scenario_levels[label["scenario_id"]].update(levels)

        unalerted_counts.update(
            item["evidence_level"]
            for item in unalerted
        )

        findings_total += len(detection["findings"])
        unalerted_total += len(unalerted)

        if (
            label["intent_annotation"] == "authorized"
            and detection["findings"]
        ):
            authorized_flagged += 1

        case_results.append({
            "case_id": case_id,
            "scenario_id": label["scenario_id"],
            "behavior_label": label["behavior_label"],
            "intent_annotation": label["intent_annotation"],
            "r001_prediction": predictions["r001_correlated"],
            "assessed_groups": len(assessments),
            "evidence_levels": dict(levels),
            "unalerted_groups": len(unalerted),
        })

    return {
        "experiment": "v0.5_explained_reporting_comparison",
        "dataset_type": "synthetic",
        "cases": len(case_results),
        "v04_predictions_preserved": True,
        "v04_finding_data_preserved": True,
        "findings": findings_total,
        "assessed_groups": sum(level_counts.values()),
        "unalerted_groups": unalerted_total,
        "authorized_cases_flagged": authorized_flagged,
        "evidence_levels": {
            level: level_counts[level]
            for level in LEVELS
        },
        "unalerted_evidence_levels": {
            level: unalerted_counts[level]
            for level in LEVELS
        },
        "scenario_levels": {
            scenario: {
                level: counts[level]
                for level in LEVELS
            }
            for scenario, counts in sorted(scenario_levels.items())
        },
        "case_results": case_results,
        "limitations": [
            "The comparison uses deterministic synthetic data.",
            "Evidence levels describe observability, not attack intent.",
            "V0.5 does not change R001 detection decisions.",
            "Multiple UID groups may belong to one test case.",
            "Production detection accuracy is not established.",
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
        "--previous",
        type=Path,
        default=ROOT / "results/benchmark-v0.4.json",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "results/compare-v0.5.json",
    )

    args = parser.parse_args()

    try:
        result = compare(args.dataset, args.previous)

        args.output.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        args.output.write_text(
            json.dumps(result, indent=2) + "\n",
            encoding="utf-8",
        )

        summary_keys = (
            "cases",
            "v04_predictions_preserved",
            "v04_finding_data_preserved",
            "findings",
            "assessed_groups",
            "unalerted_groups",
            "authorized_cases_flagged",
            "evidence_levels",
            "unalerted_evidence_levels",
        )

        print(json.dumps(
            {key: result[key] for key in summary_keys},
            indent=2,
        ))

    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
