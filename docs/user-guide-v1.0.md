# V1.0 Offline Demonstration User Guide

This guide explains how to run and interpret the
Security Log Analyzer V1.0 offline demonstration.

V1.0 is a research prototype, not a production SIEM
or a validated malicious-attack detection system.

## 1. Purpose

The demonstration combines selected normalized Zeek
connection observations with Windows or Linux failed
authentication records.

It uses the existing V0.8 endpoint-aware policy to
produce investigative candidate evidence associations.

A candidate does not establish a shared login session,
a successful attack, or malicious intent.

Ground-truth relationship labels are not loaded.

## 2. Requirements

- Python 3.11 or 3.12.
- The Security Log Analyzer repository.
- No third-party Python dependencies for this demo.
- Permission to process the input evidence.

Run all commands from the repository root.

The V1.0 demonstration must be present in the
checkout. It will become available to new clones
after the V1.0 changes are committed and published.

## 3. Supported Input Files

The command accepts two JSONL files:

1. Normalized security events.
2. Explicit host-to-IP mappings.

Each nonblank line must contain one JSON object.
Files must be valid UTF-8.

The normalized event schema version is 0.7.0.

Supported observations include selected:

- Zeek connection records.
- Windows failed network authentication records.
- Linux SSH authentication failure records.

The demonstration does not directly ingest raw EVTX,
arbitrary syslog messages, or original Zeek ASCII logs.

The included V0.9 synthetic evidence is suitable
for the documented demonstration:

- docs/evidence/v0.9/events.jsonl
- docs/evidence/v0.9/host-mappings.jsonl

The experiment's labels.jsonl file is not required
and must not be supplied as an association input.

## 4. Quick Start on Windows PowerShell

From the repository root, run:

    python scripts/demo_v10.py docs/evidence/v0.9/events.jsonl docs/evidence/v0.9/host-mappings.jsonl results/demo-v1.0-guide.json --window-seconds 120

For the included synthetic input, expect:

    Events: 32
    Host mappings: 16
    Candidate pairs: 6

The output is:

    results/demo-v1.0-guide.json

Choose a different output filename if that report
already exists. Existing reports are not overwritten.

## 5. Quick Start on macOS or Linux

Use the corresponding Python command:

    python3 scripts/demo_v10.py docs/evidence/v0.9/events.jsonl docs/evidence/v0.9/host-mappings.json results/demo-v1.0-guide.json --window-seconds 120

The input files, results, and interpretation are
the same across supported environments, subject
to successful local execution and validation.

## 6. Understanding the JSON Report

The report contains fields including:

- demo_version: demonstration version.
- input_format: normalized_jsonl.
- normalization_performed: false.
- schema_version: normalized event schema version.
- event_count: number of loaded observations.
- host_mapping_count: number of loaded mappings.
- window_seconds: maximum allowed time difference.
- candidate_pair_count: generated candidate pairs.
- protocol_not_recorded_candidate_count: candidates
  without an explicitly recorded Zeek protocol.
- candidates: candidate associations and evidence.
- limitations: interpretation and scope warnings.

Each candidate includes two event IDs.

The interpretation field contains the value
candidate_evidence_association. This indicates
an investigative candidate, not a verified attack.

The evidence includes the observed client IP,
mapped server IP, service port, host name,
network UID, time difference, and provenance
for Zeek, host logs, and host mappings.

These fields support evidence review but do not
verify a shared authentication session.

## 7. Protocol Evidence and Uncertainty

Each candidate includes evidence.protocol_status.

Possible values:

- explicit_tcp: the Zeek details explicitly
  recorded TCP.
- not_recorded: the protocol was not recorded
  in the relevant Zeek observation.

A missing protocol is not proof of TCP.

The existing association policy permits a missing
protocol value but excludes explicitly incompatible
protocol observations.

For the included 32-event V0.9 synthetic dataset,
all six returned candidates have protocol_status
set to not_recorded.

This uncertainty must not be hidden or described
as confirmed TCP traffic.

## 8. Input Validation and Errors

The demonstration rejects:

- Malformed JSON.
- JSONL lines that are not JSON objects.
- Invalid UTF-8 data.
- Empty or blank-only input files.
- Invalid normalized event schemas.
- Conflicting observations with the same event ID.
- Conflicting host mappings.
- Invalid association windows, including negative
  values and NaN.
- Output paths that already exist.

Input validation completes before the report
is created.

Existing output files are not overwritten.

An empty candidate list, when valid observations
are supplied, does not establish that the activity
was safe or that no security incident occurred.

## 9. Reproduction and Testing

Run the complete automated test suite:

    python -m unittest discover -s tests -q

On macOS or Linux, use python3 if needed.

Run V1.0 demonstration-specific tests:

    python -m unittest discover -s tests -p test_demo_v10.py -v

At this development checkpoint, 380 tests passed
locally, including 17 demonstration tests and
six performance benchmark tests.
V1.0 GitHub CI validation remains pending.

The historical V0.9 research evidence is archived
under docs/evidence/v0.9.

Do not modify archived research evidence when
running the offline demonstration.

Generated demonstration reports should be kept
under the local results/ directory.

## 10. Scope, Privacy, and Responsible Use

Use synthetic, owned, or explicitly authorized
security observations only.

Do not publicly commit private operational logs,
credentials, or identifiable personal information.

The demonstration produces candidate associations.
It does not establish:

- Malicious intent.
- Attack success.
- Verified shared sessions.
- Production detection accuracy.
- Real-world false-positive rates.
- Production throughput or operational readiness.

The V0.9 research comparison uses deliberately
constructed synthetic cases. Its performance metrics
must not be generalized to enterprise environments.

This tool is intended for reproducible research,
defensive education, and portfolio demonstration.
