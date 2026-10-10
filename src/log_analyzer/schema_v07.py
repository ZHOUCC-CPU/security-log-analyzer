
"""Validate the normalized security-event schema for V0.7."""

import ipaddress
from datetime import datetime, timedelta


SCHEMA_VERSION = "0.7.0"

SUPPORTED_TYPES = {
    "windows": {
        "windows.login_success",
        "windows.login_failure",
        "windows.special_privileges",
    },
    "linux": {
        "linux.ssh_success",
        "linux.ssh_failure",
    },
    "zeek": {
        "zeek.conn",
        "zeek.ntlm",
        "zeek.notice",
    },
}


def validate_event(event):
    """Return schema validation results without changing the input."""

    issues = []

    if not isinstance(event, dict):
        return {
            "valid": False,
            "issues": ["invalid_record"],
        }

    if event.get("schema_version") != SCHEMA_VERSION:
        issues.append("invalid_schema_version")

    event_id = event.get("event_id")
    if not isinstance(event_id, str) or not event_id.strip():
        issues.append("missing_event_id")

    uid = event.get("uid")

    if uid is not None:
        if not isinstance(uid, str) or not uid.strip():
            issues.append("invalid_uid")

    source_type = event.get("source_type")
    event_type = event.get("event_type")

    if (
        not isinstance(source_type, str)
        or source_type not in SUPPORTED_TYPES
    ):
        issues.append("unsupported_source_type")
    elif (
        not isinstance(event_type, str)
        or event_type not in SUPPORTED_TYPES[source_type]
    ):
        issues.append("unsupported_event_type")

    timestamp = event.get("timestamp_utc")

    try:
        if not isinstance(timestamp, str):
            raise ValueError("Missing timestamp")

        parsed = datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )

        if (
            parsed.tzinfo is None
            or parsed.utcoffset() != timedelta(0)
        ):
            raise ValueError("Timestamp must be UTC")

    except (ValueError, TypeError, OverflowError):
        issues.append("invalid_timestamp_utc")

    provenance = event.get("provenance")

    if not isinstance(provenance, dict):
        issues.append("invalid_provenance")

    for endpoint in ("source", "destination"):
        value = event.get(endpoint)

        if value is None:
            continue

        if not isinstance(value, dict):
            issues.append(f"invalid_{endpoint}")
            continue

        ip = value.get("ip")

        if ip is not None:
            if not isinstance(ip, str):
                issues.append(f"invalid_{endpoint}_ip")
            else:
                try:
                    ipaddress.ip_address(ip)
                except (ValueError, TypeError):
                    issues.append(f"invalid_{endpoint}_ip")

        port = value.get("port")

        if port is not None:
            if type(port) is not int or not 0 <= port <= 65535:
                issues.append(f"invalid_{endpoint}_port")

    for field in ("host", "actor"):
        value = event.get(field)

        if value is not None and not isinstance(value, dict):
            issues.append(f"invalid_{field}")

    outcome = event.get("outcome")
    if outcome is not None and not isinstance(outcome, str):
        issues.append("invalid_outcome")

    return {
        "valid": len(issues) == 0,
        "issues": sorted(set(issues)),
    }
