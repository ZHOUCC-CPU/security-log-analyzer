"""Parse Zeek ASCII and JSON logs into normalized security events."""

import argparse
import hashlib
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path


class ZeekParseError(ValueError):
    """Raised when a Zeek record cannot be parsed safely."""


def normalize_record(record, path, line_number, raw_line, log_type):
    raw_ts = record.get("ts")

    try:
        timestamp_number = float(raw_ts)
        if not math.isfinite(timestamp_number):
            raise ValueError("Timestamp must be finite")
        timestamp = datetime.fromtimestamp(
            timestamp_number, tz=timezone.utc
        ).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError, OSError) as exc:
        raise ZeekParseError(
            f"{path.name}:{line_number}: invalid timestamp: {raw_ts}"
        ) from exc

    def port_value(value):
        if value is None or value == "":
            return None
        try:
            port = int(value)
        except (ValueError, TypeError):
            return None
        return port if 0 <= port <= 65535 else None

    identity = f"{path.name}:{line_number}:{raw_line}"
    event_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()

    return {
        "event_id": event_id,
        "timestamp_utc": timestamp,
        "source_type": "zeek",
        "event_type": f"zeek.{log_type}",
        "uid": record.get("uid"),
        "source": {
            "ip": record.get("id.orig_h"),
            "port": port_value(record.get("id.orig_p")),
        },
        "destination": {
            "ip": record.get("id.resp_h"),
            "port": port_value(record.get("id.resp_p")),
        },
        "provenance": {
            "filename": path.name,
            "line_number": line_number,
        },
        "details": record,
    }


def parse_zeek(path, log_type=None):
    path = Path(path)
    log_type = log_type or path.stem

    separator = "\t"
    fields = None
    unset_field = "-"
    empty_field = "(empty)"

    with path.open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, start=1):
            raw_line = line.rstrip("\r\n")

            if not raw_line.strip():
                continue

            if raw_line.startswith("#separator "):
                encoded = raw_line[len("#separator "):]
                try:
                    separator = bytes(
                        encoded, "ascii"
                    ).decode("unicode_escape")
                except (UnicodeError, ValueError) as exc:
                    raise ZeekParseError(
                        f"{path.name}:{line_number}: bad separator"
                    ) from exc
                if not separator:
                    raise ZeekParseError("Empty separator")
                continue

            if raw_line.startswith("#fields" + separator):
                fields = raw_line.split(separator)[1:]
                continue

            if raw_line.startswith("#unset_field" + separator):
                unset_field = raw_line.split(separator, 1)[1]
                continue

            if raw_line.startswith("#empty_field" + separator):
                empty_field = raw_line.split(separator, 1)[1]
                continue

            if raw_line.startswith("#"):
                continue

            if raw_line.lstrip().startswith("{"):
                try:
                    record = json.loads(raw_line)
                except json.JSONDecodeError as exc:
                    raise ZeekParseError(
                        f"{path.name}:{line_number}: invalid JSON"
                    ) from exc
                if not isinstance(record, dict):
                    raise ZeekParseError(
                        f"{path.name}:{line_number}: expected JSON object"
                    )
            else:
                if not fields:
                    raise ZeekParseError(
                        f"{path.name}:{line_number}: missing #fields header"
                    )

                values = raw_line.split(separator)

                if len(values) != len(fields):
                    raise ZeekParseError(
                        f"{path.name}:{line_number}: "
                        f"expected {len(fields)} fields, "
                        f"received {len(values)}"
                    )

                record = {}
                for name, value in zip(fields, values):
                    if value == unset_field:
                        record[name] = None
                    elif value == empty_field:
                        record[name] = ""
                    else:
                        record[name] = value

            yield normalize_record(
                record, path, line_number, raw_line, log_type
            )


def main():
    parser = argparse.ArgumentParser(
        description="Normalize Zeek logs to JSON Lines"
    )
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--log-type")

    args = parser.parse_args()

    try:
        events = list(parse_zeek(args.input, args.log_type))
        output_text = "".join(
            json.dumps(event, ensure_ascii=False) + "\n"
            for event in events
        )

        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output_text, encoding="utf-8")
        else:
            sys.stdout.write(output_text)

        print(f"Parsed {len(events)} events.", file=sys.stderr)

    except (ZeekParseError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
