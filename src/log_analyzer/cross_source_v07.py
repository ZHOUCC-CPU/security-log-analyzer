
"""V0.7 cross-source authentication co-occurrence research.

This module produces candidate associations, not attack verdicts.
Existing V0.6 detection rules are not modified.
"""

import ipaddress
import math
from collections import defaultdict
from datetime import datetime

from .schema_v07 import validate_event


FAILURE_TYPES = {
    "windows": "windows.login_failure",
    "linux": "linux.ssh_failure",
}


def _parse_timestamp(value):
    """Parse a schema-validated UTC timestamp."""

    return datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )


def _association_key(event):
    """Return an observed IP and account key, or None.

    Missing evidence is never inferred or invented.
    Account matching is deliberately exact and case-sensitive
    for this initial experiment.
    """

    source = event.get("source")
    actor = event.get("actor")

    if not isinstance(source, dict):
        return None

    if not isinstance(actor, dict):
        return None

    source_ip = source.get("ip")
    username = actor.get("name")

    if not isinstance(source_ip, str):
        return None

    if not isinstance(username, str) or not username.strip():
        return None


    # Canonicalize the observed IP without inventing evidence.
    try:
        address = ipaddress.ip_address(source_ip)
    except ValueError:
        return None

    # An unspecified address cannot identify a remote client.
    if address.is_unspecified:
        return None

    # Multicast addresses do not identify a single client.
    if address.is_multicast:
        return None

    # Reject the IPv4 limited broadcast address.
    # Directed broadcast detection would require subnet context.
    if address == ipaddress.IPv4Address("255.255.255.255"):
        return None

    normalized_ip = str(address)

    return normalized_ip, username



def _validate_window(window_seconds):
    if (
        isinstance(window_seconds, bool)
        or not isinstance(window_seconds, (int, float))
        or not math.isfinite(window_seconds)
        or window_seconds < 0
    ):
        raise ValueError(
            "window_seconds must be a finite nonnegative number"
        )


def _make_candidate(windows_event, linux_event, key, delta):
    """Build a deterministic, evidence-focused association."""

    source_ip, username = key

    return {
        "type": "shared_source_auth_failure",
        "interpretation": "co-occurrence_only",
        "event_ids": [
            windows_event["event_id"],
            linux_event["event_id"],
        ],
        "evidence": {
            "source_ip": source_ip,
            "username": username,
            "time_delta_seconds": delta,
            "windows_timestamp_utc": (
                windows_event["timestamp_utc"]
            ),
            "linux_timestamp_utc": (
                linux_event["timestamp_utc"]
            ),
            "windows_host": (
                windows_event.get("host") or {}
            ).get("name"),
            "linux_host": (
                linux_event.get("host") or {}
            ).get("name"),
            "windows_provenance": (
                windows_event["provenance"].copy()
            ),
            "linux_provenance": (
                linux_event["provenance"].copy()
            ),
        },
    }


def find_cross_source_candidates(
    events,
    *,
    window_seconds=120,
):
    """Find Windows/Linux failed-authentication co-occurrences.

    Requirements:
      - Both records comply with the V0.7 schema.
      - One event is a Windows failed login.
      - One event is a Linux failed SSH authentication.
      - Both have the same observed source IP.
      - Both have the same exact username.
      - Absolute time difference is within the window.

    Returns deterministic candidate records.

    Raises ValueError for malformed input, invalid timestamps,
    or conflicting records with the same event ID.

    No malicious intent or shared session is inferred.
    """

    _validate_window(window_seconds)

    if not isinstance(events, (list, tuple)):
        raise ValueError(
            "events must be a list or tuple"
        )

    seen = {}

    buckets = {
        "windows": defaultdict(list),
        "linux": defaultdict(list),
    }

    for event in events:
        validation = validate_event(event)

        if not validation["valid"]:
            raise ValueError(
                "Invalid normalized event: "
                + ", ".join(validation["issues"])
            )

        event_id = event["event_id"]

        if event_id in seen:
            if seen[event_id] != event:
                raise ValueError(
                    "Conflicting records share an event ID"
                )

            # Identical duplicate observations should not
            # generate repeated associations.
            continue

        seen[event_id] = event

        source_type = event["source_type"]

        if source_type not in FAILURE_TYPES:
            continue

        if event["event_type"] != FAILURE_TYPES[source_type]:
            continue

        if event.get("outcome") != "failure":
            continue

        key = _association_key(event)

        if key is None:
            continue

        timestamp = _parse_timestamp(
            event["timestamp_utc"]
        )

        buckets[source_type][key].append(
            (timestamp, event)
        )

    candidates = []

    shared_keys = (
        buckets["windows"].keys()
        & buckets["linux"].keys()
    )

    for key in sorted(shared_keys):
        windows_records = buckets["windows"][key]
        linux_records = buckets["linux"][key]

        for windows_time, windows_event in windows_records:
            for linux_time, linux_event in linux_records:
                delta = abs(
                    (windows_time - linux_time).total_seconds()
                )

                if delta > window_seconds:
                    continue

                candidates.append(
                    _make_candidate(
                        windows_event,
                        linux_event,
                        key,
                        delta,
                    )
                )

    candidates.sort(
        key=lambda candidate: tuple(
            candidate["event_ids"]
        )
    )

    return candidates
