
"""Normalize supported Linux SSH authentication logs to V0.7 events."""

import ipaddress
import re
from datetime import datetime, timezone

from .schema_v07 import validate_event


HEADER_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"(?P<host>[A-Za-z0-9][A-Za-z0-9_.-]*)\s+"
    r"sshd\[(?P<pid>[0-9]+)\]:\s+"
    r"(?P<message>.+)$"
)

AUTH_PATTERN = re.compile(
    r"^(?P<result>Failed|Accepted)\s+"
    r"(?P<method>password|publickey)\s+"
    r"for\s+"
    r"(?P<invalid>invalid user )?"
    r"(?P<username>\S+)\s+"
    r"from\s+(?P<ip>\S+)\s+"
    r"port\s+(?P<port>[0-9]+)\s+"
    r"ssh2$"
)


def _normalize_timestamp(value):
    """Require an explicit timezone and convert the timestamp to UTC."""

    if not isinstance(value, str) or not value:
        raise ValueError("Invalid SSH timestamp")

    try:
        timestamp = value

        if timestamp.endswith("Z"):
            timestamp = timestamp[:-1] + "+00:00"

        parsed = datetime.fromisoformat(timestamp)

    except (ValueError, OverflowError) as exc:
        raise ValueError("Invalid SSH timestamp") from exc

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(
            "SSH timestamp must include an explicit timezone"
        )

    return (
        parsed.astimezone(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _validate_source(ip_text, port_text):
    """Validate the observed remote SSH endpoint."""

    try:
        address = ipaddress.ip_address(ip_text)
    except ValueError as exc:
        raise ValueError("Invalid SSH source IP") from exc

    if address.is_unspecified:
        raise ValueError(
            "Unspecified IP cannot identify an SSH client"
        )

    try:
        port = int(port_text)
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid SSH source port") from exc

    if not 1 <= port <= 65535:
        raise ValueError("SSH source port out of range")

    return {
        "ip": ip_text,
        "port": port,
    }


def normalize_linux_ssh_line(
    line,
    *,
    filename,
    line_number,
):
    """Normalize one supported SSH authentication log line.

    Supported messages:
      - Failed password
      - Failed publickey
      - Accepted password
      - Accepted publickey

    The input must use an ISO 8601 timestamp with an
    explicit timezone and an sshd[PID] message header.

    Unsupported or malformed records raise ValueError.
    """

    if not isinstance(line, str) or not line.strip():
        raise ValueError("SSH log line must be nonempty text")

    if not isinstance(filename, str) or not filename.strip():
        raise ValueError("Invalid SSH log filename")

    if type(line_number) is not int or line_number < 1:
        raise ValueError("Invalid SSH log line number")

    header = HEADER_PATTERN.fullmatch(line.strip())

    if header is None:
        raise ValueError("Unsupported SSH log header")

    timestamp_utc = _normalize_timestamp(
        header.group("timestamp")
    )

    host = header.group("host")
    sshd_pid = int(header.group("pid"))

    if sshd_pid <= 0:
        raise ValueError(
            "SSHD process ID must be positive"
        )

    message = header.group("message")

    auth = AUTH_PATTERN.fullmatch(message)

    if auth is None:
        raise ValueError(
            "Unsupported SSH authentication message"
        )

    result = auth.group("result")
    method = auth.group("method")
    username = auth.group("username")
    invalid_user = auth.group("invalid") is not None

    if result == "Accepted" and invalid_user:
        raise ValueError(
            "Accepted login cannot be marked invalid user"
        )

    source = _validate_source(
        auth.group("ip"),
        auth.group("port"),
    )

    if result == "Accepted":
        event_type = "linux.ssh_success"
        outcome = "success"
    else:
        event_type = "linux.ssh_failure"
        outcome = "failure"

    event = {
        "schema_version": "0.7.0",
        "event_id": (
            f"linux:{host}:{filename}:{line_number}"
        ),
        "timestamp_utc": timestamp_utc,
        "source_type": "linux",
        "event_type": event_type,
        "uid": None,
        "source": source,
        "destination": None,
        "host": {
            "name": host,
        },
        "actor": {
            "name": username,
            "domain": None,
        },
        "outcome": outcome,
        "details": {
            "auth_method": method,
            "invalid_user": invalid_user,
            "sshd_pid": sshd_pid,
            "protocol": "ssh2",
        },
        "provenance": {
            "filename": filename,
            "line_number": line_number,
        },
    }

    validation = validate_event(event)

    if not validation["valid"]:
        raise ValueError(
            "Normalized SSH event failed schema validation: "
            + ", ".join(validation["issues"])
        )

    return event
