"""Simple V0.9 Zeek-to-host candidate association baselines.

Baseline A: event time only.
Baseline B: observed source IP and event time.

These methods are deliberately simpler than the V0.8 policy.
Outputs are candidate event pairs, not confirmed sessions or attacks.
Ground-truth relationship labels are never used.
"""

import ipaddress
import math
from datetime import datetime

from .schema_v07 import validate_event


HOST_FAILURES = {
    "windows": "windows.login_failure",
    "linux": "linux.ssh_failure",
}


def _validate_window(window_seconds):
    if (
        type(window_seconds) not in (int, float)
        or not math.isfinite(window_seconds)
        or window_seconds < 0
    ):
        raise ValueError(
            "window_seconds must be finite and nonnegative"
        )


def _validated_unique_events(events):
    """Validate observations and reject conflicting event IDs."""

    if not isinstance(events, (list, tuple)):
        raise ValueError("events must be a list or tuple")

    unique = {}

    for event in events:
        if not isinstance(event, dict):
            raise ValueError("Invalid event record")

        try:
            result = validate_event(event)
        except (TypeError, ValueError, KeyError) as exc:
            raise ValueError("Invalid event format") from exc

        if not result["valid"]:
            raise ValueError(
                "Invalid event: " + ", ".join(result["issues"])
            )

        event_id = event["event_id"]

        if event_id in unique:
            if unique[event_id] != event:
                raise ValueError(
                    "Conflicting records share an event ID"
                )
            continue

        unique[event_id] = event

    return list(unique.values())


def _timestamp(event):
    return datetime.fromisoformat(
        event["timestamp_utc"].replace("Z", "+00:00")
    )


def _source_ip(event):
    """Return a canonical usable source IP or None."""

    endpoint = event.get("source")

    if not isinstance(endpoint, dict):
        return None

    value = endpoint.get("ip")

    if not isinstance(value, str):
        return None

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None

    if (
        address.is_unspecified
        or address.is_multicast
        or address == ipaddress.IPv4Address(
            "255.255.255.255"
        )
    ):
        return None

    return str(address)


def _is_eligible_host(event):
    """Select the host failure types supported by V0.8."""

    platform = event["source_type"]

    if platform not in HOST_FAILURES:
        return False

    if event["event_type"] != HOST_FAILURES[platform]:
        return False

    if event.get("outcome") != "failure":
        return False

    if platform == "windows":
        details = event.get("details")

        return (
            isinstance(details, dict)
            and details.get("logon_type") == 3
        )

    return True


def _find_pairs(events, window_seconds, require_source_ip):
    _validate_window(window_seconds)

    observations = _validated_unique_events(events)

    network = [
        event for event in observations
        if (
            event["source_type"] == "zeek"
            and event["event_type"] == "zeek.conn"
        )
    ]

    hosts = [
        event for event in observations
        if _is_eligible_host(event)
    ]

    results = []

    for zeek_event in network:
        zeek_time = _timestamp(zeek_event)

        for host_event in hosts:
            host_time = _timestamp(host_event)

            delta = abs(
                (host_time - zeek_time).total_seconds()
            )

            if delta > window_seconds:
                continue

            if require_source_ip:
                zeek_ip = _source_ip(zeek_event)
                host_ip = _source_ip(host_event)

                if (
                    zeek_ip is None
                    or host_ip is None
                    or zeek_ip != host_ip
                ):
                    continue

            results.append((
                zeek_event["event_id"],
                host_event["event_id"],
            ))

    results.sort()

    return results


def find_time_only_pairs(events, *, window_seconds=120):
    """Baseline A: time-only Zeek-to-host associations."""

    return _find_pairs(
        events,
        window_seconds,
        require_source_ip=False,
    )


def find_ip_time_pairs(events, *, window_seconds=120):
    """Baseline B: source-IP and time associations."""

    return _find_pairs(
        events,
        window_seconds,
        require_source_ip=True,
    )
