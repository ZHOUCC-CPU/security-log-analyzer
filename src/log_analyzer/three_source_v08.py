
"""V0.8 Zeek-to-host authentication evidence associations.

Outputs are investigative candidates, not confirmed sessions or attacks.
Synthetic ground-truth relationship labels are never used.
"""

import ipaddress
import math
from collections import defaultdict
from copy import deepcopy
from datetime import datetime

from .schema_v07 import validate_event


HOST_FAILURES = {
    "windows": ("windows.login_failure", 445),
    "linux": ("linux.ssh_failure", 22),
}


def _ip(value):
    """Canonicalize a usable endpoint IP, or return None."""
    if not isinstance(value, str):
        return None

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None

    if (
        address.is_unspecified
        or address.is_multicast
        or address == ipaddress.IPv4Address("255.255.255.255")
    ):
        return None

    return str(address)


def _endpoint_ip(event, field):
    endpoint = event.get(field)
    if not isinstance(endpoint, dict):
        return None
    return _ip(endpoint.get("ip"))


def _parse_time(event):
    return datetime.fromisoformat(
        event["timestamp_utc"].replace("Z", "+00:00")
    )


def _index_mappings(mappings):
    if not isinstance(mappings, (list, tuple)):
        raise ValueError("host_mappings must be a list or tuple")

    indexed = {}

    for mapping in mappings:
        if not isinstance(mapping, dict):
            raise ValueError("Invalid host mapping record")

        host = mapping.get("host")
        address = _ip(mapping.get("ip"))
        provenance = mapping.get("provenance")

        if (
            not isinstance(host, str)
            or not host.strip()
            or address is None
        ):
            raise ValueError("Invalid host mapping host or IP")

        if not isinstance(provenance, dict):
            raise ValueError("Invalid host mapping provenance")

        filename = provenance.get("filename")
        line = provenance.get("line_number")

        if (
            not isinstance(filename, str)
            or not filename.strip()
            or type(line) is not int
            or line < 1
        ):
            raise ValueError("Invalid host mapping provenance")

        if host in indexed:
            previous = indexed[host]
            if (
                previous["ip"] != address
                or previous["provenance"] != provenance
            ):
                raise ValueError("Conflicting host mappings")
            continue

        indexed[host] = {
            "ip": address,
            "provenance": deepcopy(provenance),
        }

    return indexed


def find_three_source_candidates(
    events,
    host_mappings,
    *,
    window_seconds=120,
):
    """Find conservative Zeek/host authentication co-occurrences."""

    if (
        type(window_seconds) not in (int, float)
        or not math.isfinite(window_seconds)
        or window_seconds < 0
    ):
        raise ValueError(
            "window_seconds must be finite and nonnegative"
        )

    if not isinstance(events, (list, tuple)):
        raise ValueError("events must be a list or tuple")

    indexed_mappings = _index_mappings(host_mappings)
    unique_events = {}

    for event in events:
        try:
            validation = validate_event(event)
        except (TypeError, ValueError, KeyError) as exc:
            raise ValueError("Invalid event format") from exc

        if not validation["valid"]:
            raise ValueError(
                "Invalid event: " + ", ".join(validation["issues"])
            )

        event_id = event["event_id"]

        if event_id in unique_events:
            if unique_events[event_id] != event:
                raise ValueError(
                    "Conflicting records share an event ID"
                )
            continue

        unique_events[event_id] = event

    network = defaultdict(list)

    for event in unique_events.values():
        if (
            event["source_type"] != "zeek"
            or event["event_type"] != "zeek.conn"
        ):
            continue

        # Explicit non-TCP traffic cannot support these
        # TCP authentication-service candidate associations.
        details = event.get("details")
        protocol = (
            details.get("proto")
            if isinstance(details, dict)
            else None
        )

        if protocol is not None and (
            not isinstance(protocol, str)
            or protocol.strip().lower() != "tcp"
        ):
            continue

        client_ip = _endpoint_ip(event, "source")
        server_ip = _endpoint_ip(event, "destination")
        destination = event.get("destination")

        port = (
            destination.get("port")
            if isinstance(destination, dict)
            else None
        )

        if (
            client_ip is None
            or server_ip is None
            or type(port) is not int
        ):
            continue

        key = (client_ip, server_ip, port)
        network[key].append((_parse_time(event), event))

    candidates = []

    for host_event in unique_events.values():
        platform = host_event["source_type"]

        if platform not in HOST_FAILURES:
            continue

        failure_type, service_port = HOST_FAILURES[platform]

        if (
            host_event["event_type"] != failure_type
            or host_event.get("outcome") != "failure"
        ):
            continue

        details = host_event.get("details")

        if platform == "windows" and (
            not isinstance(details, dict)
            or details.get("logon_type") != 3
        ):
            continue

        host = host_event.get("host")
        host_name = (
            host.get("name")
            if isinstance(host, dict)
            else None
        )

        if (
            not isinstance(host_name, str)
            or host_name not in indexed_mappings
        ):
            continue

        client_ip = _endpoint_ip(host_event, "source")

        if client_ip is None:
            continue

        mapping = indexed_mappings[host_name]
        key = (client_ip, mapping["ip"], service_port)

        for network_time, zeek_event in network.get(key, ()):
            # A recorded zero port represents unknown evidence.
            network_port = zeek_event["source"].get("port")
            host_port = host_event["source"].get("port")

            if (
                type(network_port) is int
                and type(host_port) is int
                and network_port > 0
                and host_port > 0
                and network_port != host_port
            ):
                continue

            delta = abs(
                (_parse_time(host_event) - network_time)
                .total_seconds()
            )

            if delta > window_seconds:
                continue

            candidates.append({
                "type": "zeek_host_auth_cooccurrence",
                "interpretation": "candidate_evidence_association",
                "event_ids": [
                    zeek_event["event_id"],
                    host_event["event_id"],
                ],
                "evidence": {
                    "client_ip": client_ip,
                    "server_ip": mapping["ip"],
                    "server_port": service_port,
                    "host_name": host_name,
                    "host_source_type": platform,
                    "network_uid": zeek_event.get("uid"),
                    "time_delta_seconds": delta,
                    "zeek_provenance": deepcopy(
                        zeek_event["provenance"]
                    ),
                    "host_provenance": deepcopy(
                        host_event["provenance"]
                    ),
                    "host_mapping_provenance": deepcopy(
                        mapping["provenance"]
                    ),
                },
            })

    candidates.sort(
        key=lambda item: tuple(item["event_ids"])
    )

    return candidates
