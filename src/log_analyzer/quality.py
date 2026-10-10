"""Audit normalized security-event quality without altering detection."""

import ipaddress
from collections import Counter

from .correlation import EXPECTED_TYPES, parse_timestamp


SCHEMA_VERSION = "0.6.0"


def assess_event_quality(events, sample_limit=10):
    """Report observable record-quality issues without repairing records."""

    if type(sample_limit) is not int or sample_limit < 0:
        raise ValueError("sample_limit must be a non-negative integer")

    total = 0
    affected = 0
    seen_ids = set()
    issue_counts = Counter()
    samples = []

    for index, event in enumerate(events, 1):
        total += 1
        issues = set()

        if not isinstance(event, dict):
            issues.add("invalid_record")

        else:
            event_id = event.get("event_id")

            if not isinstance(event_id, str) or not event_id.strip():
                issues.add("missing_event_id")
            elif event_id in seen_ids:
                issues.add("duplicate_event_id")
            else:
                seen_ids.add(event_id)

            if event.get("event_type") not in EXPECTED_TYPES:
                issues.add("unsupported_event_type")

            uid = event.get("uid")
            if not isinstance(uid, str) or not uid.strip():
                issues.add("missing_uid")

            try:
                parse_timestamp(event.get("timestamp_utc"))
            except (ValueError, TypeError, OverflowError):
                issues.add("invalid_timestamp")

            for endpoint in ("source", "destination"):
                value = event.get(endpoint)

                if not isinstance(value, dict):
                    issues.add(f"missing_{endpoint}")
                    continue

                address = value.get("ip")

                if address is None or address == "":
                    issues.add(f"missing_{endpoint}_ip")
                else:
                    try:
                        ipaddress.ip_address(address)
                    except (ValueError, TypeError):
                        issues.add(f"invalid_{endpoint}_ip")

                port = value.get("port")
                if port is not None:
                    if (
                        type(port) is not int
                        or not 0 <= port <= 65535
                    ):
                        issues.add(f"invalid_{endpoint}_port")

        if issues:
            affected += 1
            issue_counts.update(issues)

            if len(samples) < sample_limit:
                samples.append({
                    "record_index": index,
                    "issue_codes": sorted(issues),
                })

    return {
        "schema_version": SCHEMA_VERSION,
        "scope": "normalized_event_quality",
        "summary": {
            "total_records": total,
            "clean_records": total - affected,
            "records_with_issues": affected,
            "issue_occurrences": sum(issue_counts.values()),
        },
        "issue_counts": dict(sorted(issue_counts.items())),
        "sample_issues": samples,
        "limitations": [
            "Record quality does not establish malicious intent.",
            "Valid fields do not guarantee truthful source data.",
            "Missing records cannot be inferred from available data alone.",
            "Duplicate identification uses event_id equality.",
            "The in-memory ID set scales with unique event counts.",
            "No input records are repaired, dropped, or deduplicated.",
        ],
    }
