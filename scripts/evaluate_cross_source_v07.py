
"""Evaluate V0.7 synthetic cross-source association results.

Ground truth represents predefined synthetic activity
relationships, not confirmed attacks or shared login sessions.

All predicted pairs must have explicit ground-truth labels.
"""

from log_analyzer.cross_source_v07 import (
    find_cross_source_candidates,
)


def _safe_divide(numerator, denominator):
    """Return zero when a metric denominator is zero."""
    return numerator / denominator if denominator else 0.0


def _validate_dataset(dataset):
    """Validate dataset structure and ground-truth labels."""

    if not isinstance(dataset, dict):
        raise ValueError("Dataset must be an object")

    events = dataset.get("events")
    labels = dataset.get("labels")

    if not isinstance(events, list):
        raise ValueError("Dataset events must be a list")

    if not isinstance(labels, list):
        raise ValueError("Dataset labels must be a list")

    events_by_id = {}

    for event in events:
        if not isinstance(event, dict):
            raise ValueError("Invalid event record")

        event_id = event.get("event_id")

        if not isinstance(event_id, str) or not event_id.strip():
            raise ValueError("Invalid event ID")

        if event_id in events_by_id:
            raise ValueError(
                f"Duplicate event ID: {event_id}"
            )

        events_by_id[event_id] = event

    labels_by_pair = {}
    seen_case_ids = set()

    for label in labels:
        if not isinstance(label, dict):
            raise ValueError("Invalid label record")

        case_id = label.get("case_id")
        scenario = label.get("scenario")
        related = label.get("related")
        event_ids = label.get("event_ids")

        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError("Invalid case ID")

        if case_id in seen_case_ids:
            raise ValueError(
                f"Duplicate case ID: {case_id}"
            )

        seen_case_ids.add(case_id)

        if not isinstance(scenario, str) or not scenario.strip():
            raise ValueError("Invalid scenario name")

        if type(related) is not bool:
            raise ValueError(
                "Ground-truth related must be boolean"
            )

        if (
            not isinstance(event_ids, (list, tuple))
            or len(event_ids) != 2
        ):
            raise ValueError(
                "Each label must reference exactly two events"
            )

        if not all(
            isinstance(value, str) and value.strip()
            for value in event_ids
        ):
            raise ValueError("Invalid labeled event IDs")

        if event_ids[0] == event_ids[1]:
            raise ValueError(
                "A pair must contain two distinct events"
            )

        for event_id in event_ids:
            if event_id not in events_by_id:
                raise ValueError(
                    f"Unknown labeled event: {event_id}"
                )

        source_types = {
            events_by_id[event_id]["source_type"]
            for event_id in event_ids
        }

        if source_types != {"windows", "linux"}:
            raise ValueError(
                "Labels must reference Windows/Linux pairs"
            )

        # Treat a pair as unordered for evaluation.
        pair = tuple(sorted(event_ids))

        if pair in labels_by_pair:
            raise ValueError(
                f"Duplicate ground-truth pair: {pair}"
            )

        labels_by_pair[pair] = label

    return events, labels_by_pair


def evaluate_dataset(dataset, *, window_seconds=120):
    """Evaluate labeled synthetic cross-source associations.

    Returns:
      - confusion matrix counts
      - precision, recall and F1
      - classification of each labeled case
      - total candidate association count

    An unlabeled predicted pair raises ValueError.
    Malformed records remain processing errors, not TNs.
    """

    events, labels_by_pair = _validate_dataset(dataset)

    # Correlation does not receive ground-truth labels.
    candidates = find_cross_source_candidates(
        events,
        window_seconds=window_seconds,
    )

    predicted_pairs = set()

    for candidate in candidates:
        event_ids = candidate.get("event_ids")

        if (
            not isinstance(event_ids, list)
            or len(event_ids) != 2
        ):
            raise ValueError(
                "Correlation returned an invalid pair"
            )

        pair = tuple(sorted(event_ids))

        if pair not in labels_by_pair:
            raise ValueError(
                "Unlabeled prediction cannot be scored: "
                + repr(pair)
            )

        if pair in predicted_pairs:
            raise ValueError(
                "Duplicate predicted association"
            )

        predicted_pairs.add(pair)

    counts = {
        "tp": 0,
        "fp": 0,
        "tn": 0,
        "fn": 0,
    }

    cases = []

    for pair, label in labels_by_pair.items():
        related = label["related"]
        predicted = pair in predicted_pairs

        if related and predicted:
            classification = "TP"
        elif not related and predicted:
            classification = "FP"
        elif not related and not predicted:
            classification = "TN"
        else:
            classification = "FN"

        counts[classification.lower()] += 1

        cases.append({
            "case_id": label["case_id"],
            "scenario": label["scenario"],
            "event_ids": list(pair),
            "related": related,
            "predicted": predicted,
            "classification": classification,
        })

    # Ensure result order does not depend on input order.
    cases.sort(key=lambda item: item["case_id"])

    tp = counts["tp"]
    fp = counts["fp"]
    fn = counts["fn"]

    precision = _safe_divide(tp, tp + fp)
    recall = _safe_divide(tp, tp + fn)
    f1 = _safe_divide(
        2 * precision * recall,
        precision + recall,
    )

    return {
        "evaluation_scope": (
            "predefined_synthetic_activity_relationship"
        ),
        "production_accuracy_claim": False,
        "window_seconds": window_seconds,
        "event_count": len(events),
        "label_count": len(labels_by_pair),
        "candidate_pair_count": len(predicted_pairs),
        "counts": counts,
        "metrics": {
            "precision": precision,
            "recall": recall,
            "f1": f1,
        },
        "cases": cases,
    }
