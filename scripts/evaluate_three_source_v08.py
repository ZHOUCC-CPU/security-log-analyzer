
"""Evaluate V0.8 synthetic Zeek-to-host candidate associations.

Ground truth defines simulated activity relationships, not shared
sessions, malicious activity, or production detection accuracy.
Unknown predictions and processing errors must not be classified
as negatives.
"""

from log_analyzer.three_source_v08 import find_three_source_candidates


def _safe_divide(numerator, denominator):
    return numerator / denominator if denominator else 0.0


def _validate_dataset(dataset):
    """Verify event and label integrity before scoring."""

    if not isinstance(dataset, dict):
        raise ValueError("Dataset must be an object")

    events = dataset.get("events")
    labels = dataset.get("labels")
    host_mappings = dataset.get("host_mappings")

    if not isinstance(events, list):
        raise ValueError("Dataset events must be a list")
    if not isinstance(labels, list):
        raise ValueError("Dataset labels must be a list")
    if not isinstance(host_mappings, list):
        raise ValueError("Dataset host_mappings must be a list")

    events_by_id = {}

    for event in events:
        if not isinstance(event, dict):
            raise ValueError("Invalid event record")

        event_id = event.get("event_id")

        if not isinstance(event_id, str) or not event_id.strip():
            raise ValueError("Invalid event ID")

        if event_id in events_by_id:
            raise ValueError("Duplicate dataset event ID")

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
            raise ValueError("Duplicate case ID")

        seen_case_ids.add(case_id)

        if not isinstance(scenario, str) or not scenario.strip():
            raise ValueError("Invalid scenario")

        if type(related) is not bool:
            raise ValueError("Ground-truth related must be boolean")

        if not isinstance(event_ids, (list, tuple)) or len(event_ids) != 2:
            raise ValueError("Labels must describe two distinct events")

        if (
            not all(
                isinstance(x, str) and x.strip()
                for x in event_ids
            )
            or event_ids[0] == event_ids[1]
        ):
            raise ValueError("Invalid labeled event IDs")

        if any(x not in events_by_id for x in event_ids):
            raise ValueError("Label refers to unknown event")

        sources = {
            events_by_id[x].get("source_type")
            for x in event_ids
        }

        if (
            len(sources) != 2
            or "zeek" not in sources
            or not (
                "windows" in sources
                or "linux" in sources
            )
        ):
            raise ValueError(
                "Labels must pair Zeek with Windows or Linux"
            )

        pair = tuple(sorted(event_ids))

        if pair in labels_by_pair:
            raise ValueError("Duplicate labeled pair")

        labels_by_pair[pair] = label

    return events, host_mappings, labels_by_pair


def evaluate_dataset(dataset, *, window_seconds=120):
    """Evaluate candidates against predefined synthetic labels.

    Unlabeled candidates, invalid records and processing errors
    must not be silently converted into true negatives.
    """

    events, host_mappings, labels_by_pair = _validate_dataset(
        dataset
    )

    # The association engine receives observations and mappings only.
    # It never receives the ground-truth relationship labels.
    candidates = find_three_source_candidates(
        events,
        host_mappings,
        window_seconds=window_seconds,
    )

    predicted_pairs = set()

    for candidate in candidates:
        if not isinstance(candidate, dict):
            raise ValueError("Invalid candidate record")

        ids = candidate.get("event_ids")

        if (
            not isinstance(ids, (list, tuple))
            or len(ids) != 2
            or not all(isinstance(x, str) for x in ids)
            or ids[0] == ids[1]
        ):
            raise ValueError("Invalid predicted event pair")

        pair = tuple(sorted(ids))

        if pair not in labels_by_pair:
            raise ValueError(
                "Unlabeled candidate cannot be scored: "
                + repr(pair)
            )

        if pair in predicted_pairs:
            raise ValueError("Duplicate predicted association")

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
