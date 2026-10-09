"""Correlate normalized security events using Zeek connection UIDs."""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

EXPECTED_TYPES = ("zeek.conn", "zeek.ntlm", "zeek.notice")
MAX_SPAN_SECONDS = 300


def parse_timestamp(value):
    if not isinstance(value, str):
        raise ValueError("Missing timestamp")

    timestamp = datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )

    if timestamp.tzinfo is None:
        raise ValueError("Timestamp must include a timezone")

    return timestamp


def load_events(paths):
    events = []

    for path in paths:
        with path.open("r", encoding="utf-8-sig") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"{path}:{line_number}: invalid JSON"
                    ) from exc

                if not isinstance(event, dict):
                    raise ValueError(
                        f"{path}:{line_number}: expected JSON object"
                    )

                if not isinstance(event.get("event_type"), str):
                    raise ValueError(
                        f"{path}:{line_number}: invalid event type"
                    )

                parse_timestamp(event.get("timestamp_utc"))

                events.append(event)

    return events


def correlate_events(events):
    groups = defaultdict(list)

    for index, event in enumerate(events):
        uid = event.get("uid")

        if uid is not None and not isinstance(uid, str):
            raise ValueError("UID must be a string or null")

        # Never merge unrelated records that have no UID.
        key = f"uid:{uid}" if uid else f"unlinked:{index}"
        groups[key].append(event)

    chains = []

    for key, records in groups.items():
        ordered = sorted(
            records,
            key=lambda event: parse_timestamp(
                event["timestamp_utc"]
            ),
        )

        timestamps = [
            parse_timestamp(event["timestamp_utc"])
            for event in ordered
        ]

        first_time = timestamps[0]
        last_time = timestamps[-1]

        span_seconds = (
            last_time - first_time
        ).total_seconds()

        counts = {
            event_type: sum(
                event["event_type"] == event_type
                for event in ordered
            )
            for event_type in EXPECTED_TYPES
        }

        def get_ip(event, endpoint):
            value = event.get(endpoint)
            return value.get("ip") if isinstance(value, dict) else None

        source_ips = sorted({
            ip for event in ordered
            if (ip := get_ip(event, "source"))
        })

        destination_ips = sorted({
            ip for event in ordered
            if (ip := get_ip(event, "destination"))
        })

        consistent_endpoints = (
            len(source_ips) <= 1
            and len(destination_ips) <= 1
        )

        stage_times = {
            event_type: [
                parse_timestamp(event["timestamp_utc"])
                for event in ordered
                if event["event_type"] == event_type
            ]
            for event_type in EXPECTED_TYPES
        }

        complete_stages = all(
            counts[event_type] > 0
            for event_type in EXPECTED_TYPES
        )

        chronological = True

        if stage_times["zeek.conn"] and stage_times["zeek.ntlm"]:
            chronological = (
                min(stage_times["zeek.conn"])
                <= min(stage_times["zeek.ntlm"])
            )

        if stage_times["zeek.ntlm"] and stage_times["zeek.notice"]:
            chronological = (
                chronological
                and min(stage_times["zeek.ntlm"])
                <= min(stage_times["zeek.notice"])
            )
        valid_chain = (
            complete_stages
            and consistent_endpoints
            and chronological
            and span_seconds <= MAX_SPAN_SECONDS
        )

        if valid_chain:
            status = "complete_chain"
        elif complete_stages:
            status = "requires_review"
        elif counts["zeek.notice"] > 0:
            status = "incomplete_notice_chain"
        elif counts["zeek.ntlm"] > 0:
            status = "ntlm_without_notice"
        elif counts["zeek.conn"] > 0:
            status = "connection_only"
        else:
            status = "unclassified"

        evidence = []

        for event in ordered:
            provenance = event.get("provenance") or {}
            details = event.get("details") or {}

            evidence.append({
                "event_id": event.get("event_id"),
                "event_type": event["event_type"],
                "timestamp_utc": event["timestamp_utc"],
                "filename": provenance.get("filename"),
                "line_number": provenance.get("line_number"),
                "notice_type": details.get("note"),
            })

        chains.append({
            "uid": ordered[0].get("uid"),
            "status": status,
            "event_count": len(ordered),
            "stage_counts": counts,
            "first_timestamp_utc": ordered[0]["timestamp_utc"],
            "last_timestamp_utc": ordered[-1]["timestamp_utc"],
            "duration_ms": round(span_seconds * 1000, 3),
            "consistent_endpoints": consistent_endpoints,
            "chronological": chronological,
            "within_time_window": (
                span_seconds <= MAX_SPAN_SECONDS
            ),
            "source_ips": source_ips,
            "destination_ips": destination_ips,
            "evidence": evidence,
        })

    chains.sort(key=lambda chain: chain["first_timestamp_utc"])

    return {
        "schema_version": "0.2.0",
        "summary": {
            "total_events": len(events),
            "total_groups": len(chains),
            "complete_chains": sum(
                chain["status"] == "complete_chain"
                for chain in chains
            ),
            "connection_only_groups": sum(
                chain["status"] == "connection_only"
                for chain in chains
            ),
        },
        "chains": chains,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Correlate normalized Zeek log events"
    )

    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--output", required=True, type=Path)

    args = parser.parse_args()

    try:
        events = load_events(args.inputs)
        result = correlate_events(events)

        args.output.parent.mkdir(
            parents=True, exist_ok=True
        )

        args.output.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        print(json.dumps(result["summary"], indent=2))

    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()