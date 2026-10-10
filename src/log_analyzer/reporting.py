"""Combine detection findings with evidence quality assessments."""

from copy import deepcopy

from .evidence import assess_correlation


SCHEMA_VERSION = "0.5.0"


def build_explained_report(correlation_report, detection_report):
    """
    Enrich an existing detection report without changing detection decisions.

    Evidence completeness and rule matching remain separate concepts.
    """

    if not isinstance(correlation_report, dict):
        raise ValueError("Expected a correlation report")

    if not isinstance(detection_report, dict):
        raise ValueError("Expected a detection report")

    findings = detection_report.get("findings")

    if not isinstance(findings, list):
        raise ValueError("Detection report must contain findings")

    evidence_report = assess_correlation(correlation_report)

    assessments_by_uid = {}

    for assessment in evidence_report["assessments"]:
        uid = assessment["uid"]

        if not isinstance(uid, str) or not uid.strip():
            continue

        if uid in assessments_by_uid:
            raise ValueError(
                f"Duplicate correlation UID: {uid}"
            )

        assessments_by_uid[uid] = assessment

    enriched_findings = []
    alerted_uids = set()

    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("Invalid detection finding")

        uid = finding.get("uid")

        if not isinstance(uid, str) or not uid.strip():
            raise ValueError("Detection finding has no valid UID")

        assessment = assessments_by_uid.get(uid)

        if assessment is None:
            raise ValueError(
                f"No evidence assessment for finding UID: {uid}"
            )

        enriched = deepcopy(finding)

        enriched["evidence_assessment"] = deepcopy(assessment)

        enriched_findings.append(enriched)
        alerted_uids.add(uid)

    enriched_detection = deepcopy(detection_report)
    enriched_detection["findings"] = enriched_findings

    unalerted_assessments = [
        deepcopy(assessment)
        for assessment in evidence_report["assessments"]
        if assessment["uid"] not in alerted_uids
    ]

    return {
        "schema_version": SCHEMA_VERSION,
        "report_type": "explained_security_detection",
        "detection_report": enriched_detection,
        "evidence_report": evidence_report,
        "unalerted_assessments": unalerted_assessments,
        "summary": {
            "findings": len(enriched_findings),
            "assessed_groups": evidence_report[
                "summary"
            ]["total_groups"],
            "unalerted_groups": len(unalerted_assessments),
        },
        "limitations": [
            "Evidence completeness does not establish malicious intent.",
            "An unalerted group is not necessarily benign.",
            "Corroborated evidence can exist outside the detection policy.",
            "This report does not modify original R001 decisions.",
        ],
    }