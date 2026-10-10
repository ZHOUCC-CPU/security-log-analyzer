"""Generate independently labelled, synthetic Zeek-style security events."""

import argparse
import hashlib
import json
import random
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCENARIOS = (
    ("P01", 1, "simulated_suspicious", "Correlated NTLM and Notice"),
    ("P02", 1, "simulated_suspicious", "Correlated NTLM without Notice"),
    ("P03", 1, "authorized", "Authorized cross-boundary NTLM"),
    ("N01", 0, "not_assessed", "TCP connection only"),
    ("N02", 0, "not_assessed", "Out-of-scope destination"),
    ("N03", 0, "not_assessed", "Out-of-scope source"),
    ("N04", 0, "not_assessed", "NTLM without connection evidence"),
    ("N05", 0, "not_assessed", "Mismatched connection UIDs"),
    ("N06", 0, "not_assessed", "Conflicting endpoint addresses"),
    ("N07", 0, "not_assessed", "Reverse event chronology"),
    ("N08", 0, "not_assessed", "Correlation exceeds 300 seconds"),
)

BASE_TIME = datetime(2026, 10, 9, tzinfo=timezone.utc)


def generate(repeats, seed):
    if repeats < 1:
        raise ValueError("repeats must be at least 1")

    rng = random.Random(seed)
    specs = list(SCENARIOS) * repeats
    rng.shuffle(specs)

    events, labels = [], []

    for index, (scenario, behavior, intent, explanation) in enumerate(specs):
        case_id = f"CASE-{index + 1:05d}"
        uid = f"SYN{index + 1:08d}"
        start = BASE_TIME + timedelta(minutes=10 * index)

        octet = rng.randint(10, 190)
        src = f"10.10.20.{octet}"
        dst = f"10.10.30.{octet}"

        if scenario == "N02":
            dst = f"198.51.100.{octet}"
        elif scenario == "N03":
            src = f"192.0.2.{octet}"

        def make(kind, delta_ms, *, alternate_uid=None, alternate_src=None):
            timestamp = start + timedelta(milliseconds=delta_ms)
            key = f"{case_id}|{kind}|{delta_ms}|{alternate_uid}"

            return {
                "case_id": case_id,
                "event_id": hashlib.sha256(
                    key.encode("utf-8")
                ).hexdigest(),
                "event_type": f"zeek.{kind}",
                "uid": alternate_uid or uid,
                "timestamp_utc": timestamp.isoformat(
                    timespec="milliseconds"
                ).replace("+00:00", "Z"),
                "source": {
                    "ip": alternate_src or src,
                    "port": 50000 + index % 10000,
                },
                "destination": {
                    "ip": dst,
                    "port": 445,
                },
                "details": {
                    "note": "SYNTHETIC::Boundary_Authentication"
                } if kind == "notice" else {},
                "provenance": {
                    "filename": "synthetic-events.jsonl",
                    "line_number": None,
                },
            }

        if scenario == "N04":
            rows = [make("ntlm", 10)]
        elif scenario == "N01":
            rows = [make("conn", 0)]
        elif scenario == "N07":
            rows = [
                make("conn", 20),
                make("ntlm", 10),
            ]
        elif scenario == "N08":
            rows = [
                make("conn", 0),
                make("ntlm", 301000),
            ]
        elif scenario == "N05":
            rows = [
                make("conn", 0),
                make("ntlm", 10, alternate_uid=uid + "X"),
            ]
        elif scenario == "N06":
            rows = [
                make("conn", 0),
                make("ntlm", 10, alternate_src="10.10.20.240"),
            ]
        else:
            rows = [
                make("conn", 0),
                make("ntlm", 10),
            ]
            if scenario == "P01":
                rows.append(make("notice", 13))

        events.extend(rows)

        labels.append({
            "case_id": case_id,
            "scenario_id": scenario,
            "behavior_label": behavior,
            "intent_annotation": intent,
            "rationale": explanation,
        })

    events.sort(
        key=lambda event: (
            event["timestamp_utc"],
            event["case_id"],
            event["event_type"],
        )
    )

    for number, event in enumerate(events, 1):
        event["provenance"]["line_number"] = number

    return events, labels


def write_jsonl(path, records):
    path.write_text(
        "".join(
            json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n"
            for row in records
        ),
        encoding="utf-8",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("datasets/synthetic/v0.4"),
    )
    parser.add_argument("--seed", type=int, default=20261009)
    parser.add_argument("--repeats", type=int, default=10)

    args = parser.parse_args()

    if args.repeats < 1:
        parser.error("--repeats must be at least 1")

    events, labels = generate(args.repeats, args.seed)

    args.output.mkdir(parents=True, exist_ok=True)

    event_path = args.output / "events.jsonl"
    label_path = args.output / "labels.jsonl"

    write_jsonl(event_path, events)
    write_jsonl(label_path, labels)

    counts = Counter(
        row["behavior_label"] for row in labels
    )

    manifest = {
        "schema_version": "0.4.0",
        "dataset_type": "synthetic",
        "seed": args.seed,
        "repeats": args.repeats,
        "cases": len(labels),
        "events": len(events),
        "behavior_positive": counts[1],
        "behavior_negative": counts[0],
        "note": (
            "Labels describe observable behavior, "
            "not proven malicious intent."
        ),
        "sha256": {
            path.name: hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in (event_path, label_path)
        },
    }

    (args.output / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()