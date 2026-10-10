"""Assess completeness and consistency of correlated security evidence."""

from collections import Counter

SCHEMA_VERSION = "0.5.0"

LEVELS = (
    "corroborated",
    "partial",
    "conflicting",
    "no_relevant_evidence",
)


def assess_chain(chain):
    """Assess evidence quality without inferring malicious intent."""

    if not isinstance(chain, dict):
        raise ValueError("Expected a correlation chain object")

    counts = chain.get("stage_counts")

    if not isinstance(counts, dict):
        raise ValueError("Missing stage_counts")

    has_conn = counts.get("zeek.conn", 0) > 0
    has_ntlm = counts.get("zeek.ntlm", 0) > 0
    has_notice = counts.get("zeek.notice", 0) > 0

    uid = chain.get("uid")
    valid_uid = isinstance(uid, str) and bool(uid.strip())

    reasons = []

    if not has_conn:
        reasons.append("missing_connection")

    if not has_ntlm:
        reasons.append("missing_ntlm")

    if not valid_uid:
        reasons.append("missing_uid")

    if has_notice:
        reasons.append("notice_present")
    else:
        reasons.append("notice_absent")

    if not has_conn and not has_ntlm and not has_notice:
        level = "no_relevant_evidence"

    elif not has_conn or not has_ntlm:
        level = "partial"

    else:
        if chain.get("consistent_endpoints") is not True:
            reasons.append("endpoint_conflict")

        if chain.get("chronological") is not True:
            reasons.append("chronology_conflict")

        if chain.get("within_time_window") is not True:
            reasons.append("time_window_exceeded")

        if (
            valid_uid
            and chain.get("consistent_endpoints") is True
            and chain.get("chronological") is True
            and chain.get("within_time_window") is True
        ):
            level = "corroborated"
            reasons.append("connection_ntlm_correlated")
        else:
            level = "conflicting"

    evidence_refs = []

    for item in chain.get("evidence", []):
        evidence_refs.append({
            "event_id": item.get("event_id"),
            "event_type": item.get("event_type"),
            "filename": item.get("filename"),
            "line_number": item.get("line_number"),
        })

    return {
        "uid": uid,
        "source_chain_status": chain.get("status"),
        "evidence_level": level,
        "reason_codes": reasons,
        "observed_stages": {
            "connection": has_conn,
            "ntlm": has_ntlm,
            "notice": has_notice,
        },
        "evidence_refs": evidence_refs,
        "malicious_intent_determined": False,
    }


def assess_correlation(report):
    """Assess all correlated UID groups."""

    if not isinstance(report, dict):
        raise ValueError("Expected correlation report object")

    chains = report.get("chains")

    if not isinstance(chains, list):
        raise ValueError("Correlation report must contain chains")

    assessments = [
        assess_chain(chain)
        for chain in chains
    ]

    counts = Counter(
        item["evidence_level"]
        for item in assessments
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "assessment_scope": "evidence_completeness",
        "summary": {
            "total_groups": len(assessments),
            **{
                level: counts[level]
                for level in LEVELS
            },
        },
        "assessments": assessments,
        "limitations": [
            "Evidence completeness is not attack probability.",
            "Corroboration does not establish malicious intent.",
            "Missing telemetry is not evidence of benign activity.",
            "Separate UID groups are not automatically merged.",
            "Network trust-boundary policy is evaluated separately.",
        ],
    }