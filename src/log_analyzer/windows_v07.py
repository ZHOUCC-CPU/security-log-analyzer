
"""Normalize supported Windows Security Events into the V0.7 schema."""

import ipaddress
import re
from datetime import datetime, timezone

from .schema_v07 import validate_event


EVENT_MAPPING = {
    4624: ("windows.login_success", "success"),
    4625: ("windows.login_failure", "failure"),
    4672: ("windows.special_privileges", None),
}


def _required_text(value, field):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Missing or invalid {field}")
    return value.strip()


def _optional_text(value):
    if value is None:
        return None

    if not isinstance(value, str):
        raise ValueError("Expected a string field")

    value = value.strip()
    return value if value and value != "-" else None


def _integer(value, field):
    if isinstance(value, bool):
        raise ValueError(f"Invalid {field}")

    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and value.isdecimal():
        result = int(value)
    else:
        raise ValueError(f"Invalid {field}")

    return result

def _logon_id(value):
    """Validate a Windows hexadecimal logon identifier."""

    if not isinstance(value, str):
        raise ValueError("LogonId must be a string")

    value = value.strip()

    if not re.fullmatch(r"0[xX][0-9a-fA-F]+", value):
        raise ValueError("Invalid Windows LogonId")

    return value

def _timestamp_utc(value):
    if not isinstance(value, str):
        raise ValueError("Invalid TimeCreated")

    try:
        parsed = datetime.fromisoformat(
            value.strip().replace("Z", "+00:00")
        )
    except (ValueError, OverflowError) as exc:
        raise ValueError("Invalid TimeCreated") from exc

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("TimeCreated must include timezone")

    utc = parsed.astimezone(timezone.utc)
    return utc.isoformat().replace("+00:00", "Z")


def _source_endpoint(data):
    ip_text = _optional_text(data.get("IpAddress"))
    port_text = data.get("IpPort")


    if ip_text is None:
        # A zero port may represent unavailable source-port
        # information when Windows reports no source IP.
        if port_text is None:
            return None

        if isinstance(port_text, str):
            if port_text.strip() in ("", "-", "0"):
                return None

        if type(port_text) is int and port_text == 0:
            return None

        raise ValueError("Source port without source IP")

    try:
        ipaddress.ip_address(ip_text)
    except ValueError as exc:
        raise ValueError("Invalid Windows source IP") from exc

    port = None

    if port_text not in (None, "", "-"):
        port = _integer(port_text, "IpPort")
        if not 0 <= port <= 65535:
            raise ValueError("IpPort out of range")

    return {
        "ip": ip_text,
        "port": port,
    }


def normalize_windows_event(
    raw,
    *,
    filename,
    line_number,
):
    """Normalize one structured Windows Security Event.

    Input must be a dictionary containing EventID,
    TimeCreated, Computer, Channel, EventRecordID,
    and EventData.

    Unsupported or malformed records raise ValueError.
    The original event is never modified.
    """

    if not isinstance(raw, dict):
        raise ValueError("Windows event must be an object")

    event_id = _integer(raw.get("EventID"), "EventID")

    if event_id not in EVENT_MAPPING:
        raise ValueError(f"Unsupported Windows EventID: {event_id}")

    computer = _required_text(raw.get("Computer"), "Computer")
    channel = _required_text(raw.get("Channel"), "Channel")

    if channel.casefold() != "security":
        raise ValueError("Only Windows Security channel is supported")

    record_id = _integer(
        raw.get("EventRecordID"),
        "EventRecordID",
    )

    if record_id < 1:
        raise ValueError("EventRecordID must be positive")

    if (
        not isinstance(filename, str)
        or not filename.strip()
        or type(line_number) is not int
        or line_number < 1
    ):
        raise ValueError("Invalid event provenance")

    data = raw.get("EventData")

    if not isinstance(data, dict):
        raise ValueError("EventData must be an object")

    event_type, outcome = EVENT_MAPPING[event_id]

    if event_id == 4672:
        # Event 4672 describes assigned privileges.
        # It does not independently establish a login.
        actor_name = _optional_text(
            data.get("SubjectUserName")
        )
        actor_domain = _optional_text(
            data.get("SubjectDomainName")
        )
        source = None
    else:
        actor_name = _optional_text(
            data.get("TargetUserName")
        )
        actor_domain = _optional_text(
            data.get("TargetDomainName")
        )
        source = _source_endpoint(data)

    actor = None

    if actor_name is not None or actor_domain is not None:
        actor = {
            "name": actor_name,
            "domain": actor_domain,
        }

    details = {
        "windows_event_id": event_id,
    }

    if "LogonType" in data:
        logon_type = _integer(
            data["LogonType"],
            "LogonType",
        )

        if logon_type < 0:
            raise ValueError("Invalid LogonType")

        details["logon_type"] = logon_type

    if event_id == 4672:
        if "SubjectLogonId" in data:
            details["logon_id"] = _logon_id(
                data["SubjectLogonId"]
            )
    elif "TargetLogonId" in data:
        details["logon_id"] = _logon_id(
            data["TargetLogonId"]
        )

    event = {
        "schema_version": "0.7.0",
        "event_id": (
            f"windows:{computer}:{channel}:{record_id}"
        ),
        "timestamp_utc": _timestamp_utc(
            raw.get("TimeCreated")
        ),
        "source_type": "windows",
        "event_type": event_type,
        "uid": None,
        "source": source,
        "destination": None,
        "host": {
            "name": computer,
        },
        "actor": actor,
        "outcome": outcome,
        "details": details,
        "provenance": {
            "filename": filename,
            "line_number": line_number,
        },
    }

    validation = validate_event(event)

    if not validation["valid"]:
        raise ValueError(
            "Normalized event failed schema validation: "
            + ", ".join(validation["issues"])
        )

    return event
