"""Explainable, rule-based detection over correlated security events."""

import argparse
import ipaddress
import json
import sys
from pathlib import Path


RULE_ID = "R001_OUTBOUND_NTLM_TRUST_BOUNDARY"


def detect(report, protected_net, untrusted_net):
    """Evaluate correlated groups against an explicitly defined network boundary."""

    if not isinstance(report, dict):
        raise ValueError("Correlation report must be an object")

    chains = report.get("chains")
    if not isinstance(chains, list):
        raise ValueError("Correlation report must contain a chains list")

    protected = ipaddress.ip_network(protected_net, strict=False)
    untrusted = ipaddress.ip_network(untrusted_net, strict=False)

    findings = []
    skipped = 0

    for chain in chains:
        if not isinstance(chain, dict):
            raise ValueError("Invalid correlation group")

        status = chain.get("status")
        counts = chain.get("stage_counts", {})
        uid = chain.get("uid")

        # Do not promote incomplete or inconsistent evidence into a finding.
        eligible = (
            isinstance(uid, str)
            and bool(uid)
            and isinstance(counts, dict)
            and counts.get("zeek.conn", 0) > 0
            and counts.get("zeek.ntlm", 0) > 0
            and status in ("complete_chain", "ntlm_without_notice")
            and chain.get("consistent_endpoints") is True
            and chain.get("chronological") is True
            and chain.get("within_time_window") is True
        )

        if not eligible:
            skipped += 1
            continue

        sources = chain.get("source_ips", [])
        destinations = chain.get("destination_ips", [])

        if len(sources) != 1 or len(destinations) != 1:
            skipped += 1
            continue

        try:
            src = ipaddress.ip_address(sources[0])
            dst = ipaddress.ip_address(destinations[0])
        except (ValueError, TypeError):
            skipped += 1
            continue

        if src not in protected or dst not in untrusted:
            skipped += 1
            continue

        evidence = chain.get("evidence", [])
        if not isinstance(evidence, list):
            raise ValueError("Invalid evidence list")

        notice_types = sorted({
            event["notice_type"]
            for event in evidence
            if isinstance(event, dict)
            and event.get("event_type") == "zeek.notice"
            and isinstance(event.get("notice_type"), str)
            and event["notice_type"]
        })

        signals = ["parsed_ntlm", "configured_trust_boundary"]

        if notice_types:
            signals.append("correlated_zeek_notice")

        findings.append({
            "rule_id": RULE_ID,
            "uid": uid,
            "title": "Outbound NTLM authentication across trust boundary",
            "severity": "medium",
            "classification": "requires_investigation",
            "source_ip": str(src),
            "destination_ip": str(dst),
            "signals": signals,
            "correlated_notice_types": notice_types,
            "evidence": evidence,
            "explanation": (
                "An NTLM authentication event was correlated with "
                "a connection involving the configured protected and "
                "untrusted networks. This requires contextual review."
            ),
            "limitations": (
                "This finding does not establish malicious intent, "
                "an Outlook-specific trigger, or successful exploitation."
            ),
        })

    findings.sort(key=lambda item: item["uid"])

    return {
        "schema_version": "0.3.0",
        "rule_id": RULE_ID,
        "configuration": {
            "protected_net": str(protected),
            "untrusted_net": str(untrusted),
        },
        "summary": {
            "total_groups": len(chains),
            "findings": len(findings),
            "skipped_groups": skipped,
        },
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate correlated events against security rules"
    )

    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--protected-net", required=True)
    parser.add_argument("--untrusted-net", required=True)

    args = parser.parse_args()

    try:
        report = json.loads(args.input.read_text(encoding="utf-8-sig"))

        result = detect(
            report,
            args.protected_net,
            args.untrusted_net,
        )

        args.output.parent.mkdir(parents=True, exist_ok=True)

        args.output.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        print(json.dumps(result["summary"], indent=2))

    except (
        OSError,
        ValueError,
        TypeError,
        json.JSONDecodeError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()