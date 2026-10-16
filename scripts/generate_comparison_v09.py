"""Generate deterministic expanded V0.9 association research cases.

Relationship labels are synthetic ground truth, not attack labels.
The original V0.8 records remain unchanged.
"""

import json
from datetime import datetime, timedelta
from pathlib import Path

from generate_three_source_v08 import (
    generate_dataset,
    _make_case,
    _make_host_event,
    _address,
)
from log_analyzer.zeek_parser import normalize_record
from log_analyzer.zeek_adapter_v08 import adapt_zeek_event


EXTRA_SCENARIOS = (
    ("P04_boundary_120", True),
    ("P05_outside_120", True),
    ("P06_unknown_client_port", True),
    ("P07_port_translation", True),
    ("P08_missing_zeek_source_ip", True),
    ("N04_wrong_service_port", False),
    ("N05_udp_protocol", False),
    ("N06_wrong_client_port", False),
    ("N07_source_ip_mismatch", False),
    ("N08_ipv6_host_mapping_conflict", False),
)


def _timestamp(value):
    return datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )


def _rebuild_zeek(event, record):
    """Recalculate the event ID from the final synthetic raw record."""

    provenance = event["provenance"]
    filename = provenance["filename"]
    line_number = provenance["line_number"]

    raw_line = json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
    )

    legacy = normalize_record(
        record,
        Path(filename),
        line_number,
        raw_line,
        "conn",
    )

    return adapt_zeek_event(legacy)


def _new_case(scenario, related, ordinal, base_time):
    """Create one isolated Zeek/host pair and its mapping."""

    fixture = (
        "P03_linux_ipv6"
        if scenario == "N08_ipv6_host_mapping_conflict"
        else scenario
    )

    pair, mapping, label = _make_case(
        fixture,
        related,
        ordinal,
        base_time,
    )

    zeek, host = pair
    record = dict(zeek["details"])
    rebuild_network = False

    if scenario in ("P04_boundary_120", "P05_outside_120"):
        offset = 120 if scenario == "P04_boundary_120" else 121

        network_time = _timestamp(zeek["timestamp_utc"])

        host = _make_host_event(
            "linux",
            host["host"]["name"],
            host["actor"]["name"],
            host["source"]["ip"],
            network_time + timedelta(seconds=offset),
            ordinal,
        )

    elif scenario == "P06_unknown_client_port":
        record["id.orig_p"] = 0
        rebuild_network = True

    elif scenario == "P07_port_translation":
        record["id.orig_p"] = 53123
        rebuild_network = True

    elif scenario == "P08_missing_zeek_source_ip":
        record["id.orig_h"] = None
        rebuild_network = True

    elif scenario == "N04_wrong_service_port":
        record["id.resp_p"] = 2222
        rebuild_network = True

    elif scenario == "N05_udp_protocol":
        record["proto"] = "udp"
        rebuild_network = True

    elif scenario == "N06_wrong_client_port":
        record["id.orig_p"] = 53124
        rebuild_network = True

    elif scenario == "N07_source_ip_mismatch":
        record["id.orig_h"] = "198.19.0.77"
        rebuild_network = True

    elif scenario == "N08_ipv6_host_mapping_conflict":
        mapping["ip"] = _address(
            "2001:db8:3::1",
            ordinal,
        )

    if rebuild_network:
        zeek = _rebuild_zeek(zeek, record)

    label["scenario"] = scenario
    label["related"] = related
    label["event_ids"] = [
        zeek["event_id"],
        host["event_id"],
    ]

    return [zeek, host], mapping, label


def generate_expanded_dataset(repeats=1, seed=20261011):
    """Return 16 scenario types with detached observations and labels."""

    dataset = generate_dataset(
        repeats=repeats,
        seed=seed,
    )

    # The first V0.8 Zeek observation is at ordinal zero.
    # Reuse its timestamp to preserve the original seed.
    base_time = _timestamp(
        dataset["events"][0]["timestamp_utc"]
    )

    first_ordinal = len(dataset["labels"])

    for repeat_index in range(repeats):
        for index, (scenario, related) in enumerate(EXTRA_SCENARIOS):
            ordinal = (
                first_ordinal
                + repeat_index * len(EXTRA_SCENARIOS)
                + index
            )

            pair, mapping, label = _new_case(
                scenario,
                related,
                ordinal,
                base_time,
            )

            dataset["events"].extend(pair)
            dataset["host_mappings"].append(mapping)
            dataset["labels"].append(label)

    manifest = dataset["manifest"]

    manifest["dataset_version"] = "v0.9"
    manifest["scenario_count"] = 16
    manifest["event_count"] = len(dataset["events"])
    manifest["label_count"] = len(dataset["labels"])
    manifest["host_mapping_count"] = len(
        dataset["host_mappings"]
    )

    manifest["positive_count"] = sum(
        item["related"] is True
        for item in dataset["labels"]
    )

    manifest["negative_count"] = sum(
        item["related"] is False
        for item in dataset["labels"]
    )

    manifest["production_accuracy_claim"] = False

    return dataset
