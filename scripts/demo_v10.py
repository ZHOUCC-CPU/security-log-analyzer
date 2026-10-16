"""V1.0 offline security evidence association demonstration.

Input: normalized JSONL events and explicit host mappings.
Output: investigative candidate associations with provenance.

This demonstration does not normalize raw logs, use labels,
confirm sessions, or identify proven attacks.
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from log_analyzer.schema_v07 import SCHEMA_VERSION
from log_analyzer.three_source_v08 import (
    find_three_source_candidates,
)


def _read_jsonl(path):
    """Read JSONL and reject malformed or non-object records."""

    source = Path(path)
    records = []

    try:
        with source.open("r", encoding="utf-8-sig") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue

                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"{source.name}:{line_number}: invalid JSON"
                    ) from exc

                if not isinstance(record, dict):
                    raise ValueError(
                        f"{source.name}:{line_number}: "
                        "expected a JSON object"
                    )

                records.append(record)

    except UnicodeError as exc:
        raise ValueError(
            f"{source.name}: invalid UTF-8 input"
        ) from exc

    if not records:
        raise ValueError(
            f"{source.name}: no JSONL records found"
        )

    return records


def run_demo(
    events_path,
    mappings_path,
    output_path,
    *,
    window_seconds=120,
):
    """Run the existing candidate policy on normalized evidence.

    Ground-truth labels are deliberately not loaded.
    Existing output files cannot be overwritten.
    """

    destination = Path(output_path)

    if destination.exists() or destination.is_symlink():
        raise FileExistsError(
            f"Output already exists: {destination}"
        )

    events = _read_jsonl(events_path)
    mappings = _read_jsonl(mappings_path)

    # The existing V0.8 engine validates event schemas,
    # mapping provenance, duplicates, and the time window.
    candidates = find_three_source_candidates(
        events,
        mappings,
        window_seconds=window_seconds,
    )

    # The association engine returns one Zeek event ID first.
    # Enrich its candidates without modifying the V0.8 engine.
    event_by_id = {
        event["event_id"]: event
        for event in events
    }

    protocol_not_recorded_count = 0

    for candidate in candidates:
        zeek_id = candidate["event_ids"][0]
        zeek_event = event_by_id[zeek_id]

        details = zeek_event.get("details")
        protocol = (
            details.get("proto")
            if isinstance(details, dict)
            else None
        )

        if protocol is None:
            protocol_status = "not_recorded"
            protocol_not_recorded_count += 1
        elif (
            isinstance(protocol, str)
            and protocol.strip().lower() == "tcp"
        ):
            protocol_status = "explicit_tcp"
        else:
            raise ValueError(
                "Unexpected protocol in candidate evidence"
            )

        candidate["evidence"]["protocol_status"] = (
            protocol_status
        )

    report = {
        "demo_version": "v1.0",
        "input_format": "normalized_jsonl",
        "normalization_performed": False,
        "schema_version": SCHEMA_VERSION,
        "evaluation_scope": "offline_candidate_evidence_association",
        "production_accuracy_claim": False,
        "window_seconds": window_seconds,
        "source_files": {
            "events": Path(events_path).name,
            "host_mappings": Path(mappings_path).name,
        },
        "event_count": len(events),
        "host_mapping_count": len(mappings),
        "candidate_pair_count": len(candidates),
        "protocol_not_recorded_candidate_count": (
            protocol_not_recorded_count
        ),
        "candidates": candidates,
        "limitations": [
            "Candidates do not prove a shared session.",
            "Candidates do not prove an attack.",
            "Input observations must already be normalized.",
            "No ground-truth labels are used.",
            "Missing protocol evidence is not proof of TCP.",
            "Host mappings are supplied external evidence.",
            "Synthetic results do not establish production accuracy.",
        ],
    }

    payload = (
        json.dumps(
            report,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        ) + "\n"
    ).encode("utf-8")

    # All input validation finishes before output creation.
    destination.parent.mkdir(parents=True, exist_ok=True)

    # Exclusive creation protects existing files even if
    # another process creates the path after our check.
    with destination.open("xb") as handle:
        handle.write(payload)

    return report


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Offline demonstration of candidate security "
            "evidence associations."
        )
    )

    parser.add_argument(
        "events",
        type=Path,
        help="Normalized security events JSONL",
    )

    parser.add_argument(
        "host_mappings",
        type=Path,
        help="Explicit host-to-IP mappings JSONL",
    )

    parser.add_argument(
        "output",
        type=Path,
        help="New JSON report path",
    )

    parser.add_argument(
        "--window-seconds",
        type=float,
        default=120,
        help="Maximum absolute timestamp difference",
    )

    args = parser.parse_args()

    try:
        result = run_demo(
            args.events,
            args.host_mappings,
            args.output,
            window_seconds=args.window_seconds,
        )

    except (ValueError, OSError) as exc:
        parser.exit(1, f"ERROR: {exc}\n")

    print("[PASS] V1.0 offline demonstration completed")
    print("Events:", result["event_count"])
    print("Host mappings:", result["host_mapping_count"])
    print("Candidate pairs:", result["candidate_pair_count"])
    print("Output:", args.output)


if __name__ == "__main__":
    main()
