"""Generate deterministic, labeled V0.8 three-source synthetic evidence.

Ground truth describes predefined simulated activity relationships,
not verified shared sessions, attacks, or production detection accuracy.
This generator writes no files and never supplies labels to the events.
"""

import ipaddress
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from log_analyzer.linux_ssh_v07 import normalize_linux_ssh_line
from log_analyzer.windows_v07 import normalize_windows_event
from log_analyzer.zeek_adapter_v08 import adapt_zeek_event
from log_analyzer.zeek_parser import normalize_record


SCENARIOS = (
    ("P01_windows_ipv4", True),
    ("P02_linux_ipv4", True),
    ("P03_linux_ipv6", True),
    ("N01_nat_collision", False),
    ("N02_reversed_direction", False),
    ("N03_wrong_host_mapping", False),
)


def _utc_text(timestamp):
    return timestamp.astimezone(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


def _address(base, offset):
    base_address = ipaddress.ip_address(base)
    return str(ipaddress.ip_address(int(base_address) + offset))


def _make_host_event(platform, host, username, client_ip, timestamp, ordinal):
    line_number = ordinal + 1

    if platform == "windows":
        raw = {
            "EventID": 4625,
            "TimeCreated": _utc_text(timestamp),
            "Computer": host,
            "Channel": "Security",
            "EventRecordID": line_number,
            "EventData": {
                "TargetUserName": username,
                "TargetDomainName": "LAB",
                "IpAddress": client_ip,
                "IpPort": "53122",
                "LogonType": 3,
            },
        }
        return normalize_windows_event(
            raw,
            filename="synthetic-windows.jsonl",
            line_number=line_number,
        )

    line = (
        f"{_utc_text(timestamp)} {host} sshd[{1000 + ordinal}]: "
        f"Failed password for {username} "
        f"from {client_ip} port 53122 ssh2"
    )
    return normalize_linux_ssh_line(
        line,
        filename="synthetic-linux.log",
        line_number=line_number,
    )


def _make_zeek_event(origin_ip, responder_ip, responder_port, timestamp,
                     ordinal):
    record = {
        "ts": timestamp.timestamp(),
        "uid": f"SYN-ZEEK-{ordinal:06d}",
        "id.orig_h": origin_ip,
        "id.orig_p": 53122,
        "id.resp_h": responder_ip,
        "id.resp_p": responder_port,
    }
    raw_line = json.dumps(record, sort_keys=True, separators=(",", ":"))
    legacy = normalize_record(
        record,
        Path("synthetic-conn.log"),
        ordinal + 1,
        raw_line,
        "conn",
    )
    return adapt_zeek_event(legacy)


def _make_case(scenario, related, ordinal, base_time):
    network_time = base_time + timedelta(minutes=ordinal * 10)
    host_time = network_time + timedelta(seconds=45)
    ipv6 = scenario == "P03_linux_ipv6"

    if ipv6:
        client_ip = _address("2001:db8:1::1", ordinal)
        server_ip = _address("2001:db8:2::1", ordinal)
        alternate_ip = _address("2001:db8:3::1", ordinal)
    else:
        client_ip = _address("198.18.0.10", ordinal)
        server_ip = _address("203.0.113.10", ordinal)
        alternate_ip = _address("192.0.2.10", ordinal)

    platform = (
        "windows"
        if scenario in (
            "P01_windows_ipv4",
            "N01_nat_collision",
            "N03_wrong_host_mapping",
        )
        else "linux"
    )
    host = (
        f"LAB-WIN-{ordinal:05d}"
        if platform == "windows"
        else f"lab-linux-{ordinal:05d}"
    )
    username = f"synthetic_user_{ordinal}"
    service_port = 445 if platform == "windows" else 22

    network_origin = client_ip
    network_responder = server_ip
    if scenario == "N02_reversed_direction":
        network_origin = server_ip
        network_responder = client_ip

    mapped_ip = (
        alternate_ip
        if scenario == "N03_wrong_host_mapping"
        else server_ip
    )

    zeek_event = _make_zeek_event(
        network_origin, network_responder, service_port,
        network_time, ordinal,
    )
    host_event = _make_host_event(
        platform, host, username, client_ip, host_time, ordinal,
    )
    host_mapping = {
        "host": host,
        "ip": mapped_ip,
        "provenance": {
            "filename": "synthetic-host-mappings.jsonl",
            "line_number": ordinal + 1,
        },
    }
    label = {
        "case_id": f"TS-{ordinal:06d}",
        "scenario": scenario,
        "related": related,
        "event_ids": [zeek_event["event_id"], host_event["event_id"]],
    }
    return [zeek_event, host_event], host_mapping, label


def generate_dataset(repeats=1, seed=20261011):
    """Return synthetic events, independent labels, mappings and manifest."""
    if type(repeats) is not int or repeats < 1:
        raise ValueError("repeats must be a positive integer")
    if type(seed) is not int:
        raise ValueError("seed must be an integer")

    rng = random.Random(seed)
    base_time = datetime(
        2026, 10, 11, 8, 0, tzinfo=timezone.utc
    ) + timedelta(seconds=rng.randrange(60))

    events = []
    labels = []
    host_mappings = []

    for repeat_index in range(repeats):
        for scenario_index, (scenario, related) in enumerate(SCENARIOS):
            ordinal = repeat_index * len(SCENARIOS) + scenario_index
            pair, mapping, label = _make_case(
                scenario, related, ordinal, base_time
            )
            events.extend(pair)
            host_mappings.append(mapping)
            labels.append(label)

    manifest = {
        "dataset_version": "v0.8-phase2",
        "schema_version": "0.7.0",
        "seed": seed,
        "repeats": repeats,
        "scenario_count": len(SCENARIOS),
        "event_count": len(events),
        "label_count": len(labels),
        "host_mapping_count": len(host_mappings),
        "positive_count": sum(item["related"] is True for item in labels),
        "negative_count": sum(item["related"] is False for item in labels),
        "label_definition": "predefined_synthetic_activity_relationship",
        "production_accuracy_claim": False,
    }
    return {
        "events": events,
        "labels": labels,
        "host_mappings": host_mappings,
        "manifest": manifest,
    }
