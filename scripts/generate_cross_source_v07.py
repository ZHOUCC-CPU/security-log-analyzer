
"""Generate deterministic V0.7 cross-source research datasets.

Ground-truth labels describe predefined synthetic activity
relationships, not confirmed attacks or real login sessions.

This module generates data in memory and does not write files.
"""

import ipaddress
import random
from datetime import datetime, timedelta, timezone


SCENARIOS = (
    ("P01_shared_activity", True),
    ("P02_ipv6_shared_activity", True),
    ("P03_time_boundary", True),
    ("P04_delayed_related_activity", True),
    ("N01_different_ip", False),
    ("N02_different_username", False),
    ("N03_unrelated_outside_window", False),
    ("N04_nat_collision", False),
    ("N05_shared_account_collision", False),
    ("N06_missing_endpoint", False),
    ("N07_success_not_failure", False),
    ("N08_multicast_source", False),
)


def _utc_text(value):
    """Format a timezone-aware UTC datetime."""

    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _make_event(
    *,
    event_id,
    source_type,
    timestamp,
    source_ip,
    username,
    ordinal,
    event_type=None,
    outcome="failure",
):
    """Create one normalized synthetic security event."""

    if source_type == "windows":
        default_event_type = "windows.login_failure"
        host_name = f"LAB-WIN-{ordinal:05d}"
        filename = "synthetic-windows.jsonl"
    elif source_type == "linux":
        default_event_type = "linux.ssh_failure"
        host_name = f"LAB-LINUX-{ordinal:05d}"
        filename = "synthetic-linux.jsonl"
    else:
        raise ValueError("Unsupported synthetic source type")

    source = None

    if source_ip is not None:
        source = {
            "ip": source_ip,
            "port": 53122,
        }

    return {
        "schema_version": "0.7.0",
        "event_id": event_id,
        "timestamp_utc": _utc_text(timestamp),
        "source_type": source_type,
        "event_type": event_type or default_event_type,
        "uid": None,
        "source": source,
        "destination": None,
        "host": {
            "name": host_name,
        },
        "actor": {
            "name": username,
            "domain": None,
        },
        "outcome": outcome,
        "details": {
            "synthetic": True,
        },
        "provenance": {
            "filename": filename,
            "line_number": ordinal + 1,
        },
    }


def _scenario_pair(
    scenario,
    related,
    ordinal,
    base_time,
):
    """Build a labeled pair of synthetic observations.

    Case time slots are separated to avoid accidental
    cross-case associations within a 120-second window.
    """

    first_time = base_time + timedelta(
        minutes=ordinal * 10
    )

    delta_seconds = 45

    if scenario == "P03_time_boundary":
        delta_seconds = 120

    if scenario in (
        "P04_delayed_related_activity",
        "N03_unrelated_outside_window",
    ):
        delta_seconds = 180

    second_time = first_time + timedelta(
        seconds=delta_seconds
    )

    # Use a benchmark address range for synthetic IPv4 data.
    ipv4_base = int(
        ipaddress.IPv4Address("198.18.0.1")
    )

    source_ip = str(
        ipaddress.IPv4Address(ipv4_base + ordinal)
    )

    if scenario == "P02_ipv6_shared_activity":
        ipv6_base = int(
            ipaddress.IPv6Address("2001:db8::1")
        )

        source_ip = str(
            ipaddress.IPv6Address(ipv6_base + ordinal)
        )

    if scenario == "N08_multicast_source":
        source_ip = "224.0.0.1"

    username = f"synthetic_user_{ordinal}"

    windows_id = f"SYN-V07-{ordinal:06d}-WIN"
    linux_id = f"SYN-V07-{ordinal:06d}-LINUX"

    windows = _make_event(
        event_id=windows_id,
        source_type="windows",
        timestamp=first_time,
        source_ip=source_ip,
        username=username,
        ordinal=ordinal,
    )

    linux = _make_event(
        event_id=linux_id,
        source_type="linux",
        timestamp=second_time,
        source_ip=source_ip,
        username=username,
        ordinal=ordinal,
    )

    if scenario == "N01_different_ip":
        other_base = int(
            ipaddress.IPv4Address("203.0.113.1")
        )
        linux["source"]["ip"] = str(
            ipaddress.IPv4Address(other_base + ordinal)
        )

    elif scenario == "N02_different_username":
        linux["actor"]["name"] = username + "_other"

    elif scenario == "N06_missing_endpoint":
        windows["source"] = None

    elif scenario == "N07_success_not_failure":
        windows["event_type"] = "windows.login_success"
        windows["outcome"] = "success"

    # N04 NAT collision:
    # Two unrelated simulated activities have identical
    # observed source IPs, usernames and nearby timestamps.
    #
    # N05 shared-account collision:
    # Two unrelated simulated activities share the same
    # visible account and source IP characteristics.
    #
    # Neither ground-truth label is included in the events.
    # The correlation engine is deliberately not given
    # access to synthetic activity relationships.

    label = {
        "case_id": f"CS-{ordinal:06d}",
        "scenario": scenario,
        "related": related,
        "event_ids": [
            windows_id,
            linux_id,
        ],
    }

    return windows, linux, label


def generate_dataset(repeats=1, seed=20261010):
    """Generate reproducible cross-source benchmark records.

    Each repetition contains:
      - 12 labeled cases
      - 24 normalized events
      - 4 related pairs
      - 8 unrelated pairs

    Labels represent synthetic activity relationships.
    They are independent of correlation predictions.
    """

    if type(repeats) is not int or repeats < 1:
        raise ValueError(
            "repeats must be a positive integer"
        )

    if type(seed) is not int:
        raise ValueError(
            "seed must be an integer"
        )

    rng = random.Random(seed)

    # The seed controls a deterministic time offset.
    initial_offset = rng.randrange(60)

    base_time = datetime(
        2026, 10, 10, 8, 0, 0,
        tzinfo=timezone.utc,
    ) + timedelta(seconds=initial_offset)

    events = []
    labels = []

    for repeat_index in range(repeats):
        for scenario_index, (
            scenario,
            related,
        ) in enumerate(SCENARIOS):

            ordinal = (
                repeat_index * len(SCENARIOS)
                + scenario_index
            )

            windows, linux, label = _scenario_pair(
                scenario=scenario,
                related=related,
                ordinal=ordinal,
                base_time=base_time,
            )

            events.extend((windows, linux))
            labels.append(label)

    positive_count = sum(
        label["related"] is True
        for label in labels
    )

    negative_count = sum(
        label["related"] is False
        for label in labels
    )

    manifest = {
        "dataset_version": "v0.7",
        "schema_version": "0.7.0",
        "seed": seed,
        "repeats": repeats,
        "scenario_count": len(SCENARIOS),
        "event_count": len(events),
        "label_count": len(labels),
        "positive_count": positive_count,
        "negative_count": negative_count,
        "label_definition": (
            "predefined_synthetic_activity_relationship"
        ),
        "evaluation_scope": (
            "windows_linux_authentication_cooccurrence"
        ),
        "production_accuracy_claim": False,
    }

    return {
        "events": events,
        "labels": labels,
        "manifest": manifest,
    }
