"""Evaluate V0.9 synthetic candidate association methods.

All three methods use the same predefined labeled pair universe.
Ground-truth labels are used only for scoring, never association.
Results are not estimates of production detection accuracy.
"""

import math

from evaluate_three_source_v08 import _validate_dataset
from log_analyzer.association_baselines_v09 import (
    find_time_only_pairs,
    find_ip_time_pairs,
)
from log_analyzer.three_source_v08 import (
    find_three_source_candidates,
)


def _validate_window(window_seconds):
    if (
        type(window_seconds) not in (int, float)
        or not math.isfinite(window_seconds)
        or window_seconds < 0
    ):
        raise ValueError(
            "window_seconds must be finite and nonnegative"
        )


def _normalize_predictions(candidates, labels_by_pair):
    """Validate predicted pairs before classification."""

    if not isinstance(candidates, (list, tuple)):
        raise ValueError("Predictions must be a list or tuple")

    predicted = set()

    for item in candidates:
        ids = (
            item.get("event_ids")
            if isinstance(item, dict)
            else item
        )

        if (
            not isinstance(ids, (list, tuple))
            or len(ids) != 2
            or not all(
                isinstance(value, str) and value.strip()
                for value in ids
            )
            or ids[0] == ids[1]
        ):
            raise ValueError("Invalid predicted event pair")

        pair = tuple(sorted(ids))

        if pair not in labels_by_pair:
            raise ValueError(
                "Unlabeled prediction cannot be scored: "
                + repr(pair)
            )

        if pair in predicted:
            raise ValueError(
                "Duplicate predicted association: "
                + repr(pair)
            )

        predicted.add(pair)

    return predicted


def _score_method(candidates, labels_by_pair):
    """Score one method against the frozen synthetic labels."""

    predicted = _normalize_predictions(
        candidates,
        labels_by_pair,
    )

    counts = {
        "tp": 0,
        "fp": 0,
        "tn": 0,
        "fn": 0,
    }

    cases = []

    for pair, label in labels_by_pair.items():
        related = label["related"]
        matched = pair in predicted

        if related and matched:
            classification = "TP"
        elif not related and matched:
            classification = "FP"
        elif not related and not matched:
            classification = "TN"
        else:
            classification = "FN"

        counts[classification.lower()] += 1

        cases.append({
            "case_id": label["case_id"],
            "scenario": label["scenario"],
            "event_ids": list(pair),
            "related": related,
            "predicted": matched,
            "classification": classification,
        })

    cases.sort(key=lambda item: item["case_id"])

    tp = counts["tp"]
    fp = counts["fp"]
    fn = counts["fn"]

    precision = (
        tp / (tp + fp)
        if tp + fp
        else 0.0
    )

    recall = (
        tp / (tp + fn)
        if tp + fn
        else 0.0
    )

    f1 = (
        2 * tp / (2 * tp + fp + fn)
        if 2 * tp + fp + fn
        else 0.0
    )

    return {
        "candidate_pair_count": len(predicted),
        "counts": counts,
        "metrics": {
            "precision": precision,
            "recall": recall,
            "f1": f1,
        },
        "cases": cases,
    }


def evaluate_comparison(dataset, *, window_seconds=120):
    """Compare time, IP-time and V0.8 policy associations."""

    _validate_window(window_seconds)

    # Reuse the established V0.8 input-integrity checks.
    # The archived V0.8 implementation is not modified.
    events, mappings, labels_by_pair = _validate_dataset(
        dataset
    )

    # Ground-truth labels are NOT supplied to any method.
    time_candidates = find_time_only_pairs(
        events,
        window_seconds=window_seconds,
    )

    ip_candidates = find_ip_time_pairs(
        events,
        window_seconds=window_seconds,
    )

    policy_candidates = find_three_source_candidates(
        events,
        mappings,
        window_seconds=window_seconds,
    )

    methods = {
        "time_only": _score_method(
            time_candidates,
            labels_by_pair,
        ),
        "ip_time": _score_method(
            ip_candidates,
            labels_by_pair,
        ),
        "v08_policy": _score_method(
            policy_candidates,
            labels_by_pair,
        ),
    }

    return {
        "evaluation_scope": (
            "predefined_synthetic_activity_relationship"
        ),
        "production_accuracy_claim": False,
        "window_seconds": window_seconds,
        "event_count": len(events),
        "label_count": len(labels_by_pair),
        "methods": methods,
    }
