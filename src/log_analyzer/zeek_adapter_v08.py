
"""Adapt legacy Zeek events to the V0.7 unified event schema.

V0.8 compatibility layer:
- Preserve existing Zeek event identifiers and evidence.
- Never fabricate host, actor, or authentication outcome.
- Never mutate the original observation.
- Keep legacy Zeek detection behavior independent.
"""

from copy import deepcopy

from .schema_v07 import SCHEMA_VERSION, validate_event


SUPPORTED_ZEEK_TYPES = {
    "zeek.conn",
    "zeek.ntlm",
    "zeek.notice",
}


def adapt_zeek_event(event):
    """Return a detached, schema-compatible Zeek event.

    Accepts legacy normalized Zeek event dictionaries.

    Existing evidence fields are preserved, including:
    - event_id
    - timestamp_utc
    - uid
    - source and destination
    - provenance
    - details

    Invalid or unsupported input raises ValueError.
    """

    if not isinstance(event, dict):
        raise ValueError("Zeek event must be an object")

    if event.get("source_type") != "zeek":
        raise ValueError("Expected a Zeek source event")

    event_type = event.get("event_type")

    if (
        not isinstance(event_type, str)
        or event_type not in SUPPORTED_ZEEK_TYPES
    ):
        raise ValueError(
            "Unsupported Zeek event type"
        )

    # Do not silently convert an explicitly incompatible
    # schema version into a valid V0.7 observation.
    if "schema_version" in event:
        if event["schema_version"] != SCHEMA_VERSION:
            raise ValueError(
                "Incompatible existing schema version"
            )

    # Deep copy is required to detach nested evidence,
    # endpoint dictionaries, and provenance records.
    normalized = deepcopy(event)

    # Legacy Zeek records have no schema_version.
    normalized["schema_version"] = SCHEMA_VERSION

    # These fields cannot be inferred from the legacy
    # network observation alone.
    normalized.setdefault("host", None)
    normalized.setdefault("actor", None)
    normalized.setdefault("outcome", None)

    # Preserve the original Zeek UID, including its absence.
    normalized.setdefault("uid", None)

    # Preserve missing endpoints as unknown; never invent
    # IP addresses or destination information.
    normalized.setdefault("source", None)
    normalized.setdefault("destination", None)

    # Legacy normalizer supplies a details dictionary.
    # Malformed evidence structures must be rejected.
    details = normalized.get("details")

    if not isinstance(details, dict):
        raise ValueError(
            "Zeek event details must be an object"
        )

    # Provenance must identify a real source-file position.
    provenance = normalized.get("provenance")

    if not isinstance(provenance, dict):
        raise ValueError(
            "Zeek provenance must be an object"
        )

    filename = provenance.get("filename")
    line_number = provenance.get("line_number")

    if (
        not isinstance(filename, str)
        or not filename.strip()
    ):
        raise ValueError(
            "Invalid Zeek provenance filename"
        )

    if type(line_number) is not int or line_number < 1:
        raise ValueError(
            "Invalid Zeek provenance line number"
        )

    # Validate the adapted record before returning it.
    validation = validate_event(normalized)

    if not validation["valid"]:
        raise ValueError(
            "Zeek event failed unified schema validation: "
            + ", ".join(validation["issues"])
        )

    return normalized