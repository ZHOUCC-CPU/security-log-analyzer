# V0.7 Research Design: Multi-Source Security Log Analysis

## 1. Research objective

Extend the existing Zeek-oriented security log analyzer with independent Windows Security Event and Linux SSH authentication log adapters.

Investigate whether cross-source evidence can improve investigative context while controlling incorrect event associations.

This is a research prototype, not a production SIEM.

## 2. Supported sources

### Zeek

Existing event types:
- `zeek.conn`
- `zeek.ntlm`
- `zeek.notice`

Existing V0.6 behavior must remain compatible.

### Windows Security Events

Initial event types:
- `windows.login_success`: Windows Event ID 4624
- `windows.login_failure`: Windows Event ID 4625
- `windows.special_privileges`: Windows Event ID 4672

Event 4672 indicates special privileges assigned to a logon. It must not be interpreted as independent proof of successful authentication or malicious activity.

### Linux SSH

Initial event types:
- `linux.ssh_success`
- `linux.ssh_failure`

Initial scope is SSH authentication evidence from controlled, synthetic, or explicitly authorized logs.

## 3. Normalized event schema

Required fields:
- `schema_version`: string
- `event_id`: string
- `timestamp_utc`: timezone-aware UTC timestamp
- `source_type`: string
- `event_type`: string
- `provenance`: object

Common optional fields:
- `uid`: string or null
- `source`: object or null
- `destination`: object or null
- `host`: object or null
- `actor`: object or null
- `outcome`: string or null
- `details`: object

Example Windows event:

```json
{
  "schema_version": "0.7.0",
  "event_id": "SYN-WIN-0001",
  "timestamp_utc": "2026-10-10T08:00:00Z",
  "source_type": "windows",
  "event_type": "windows.login_failure",
  "uid": null,
  "source": {"ip": "192.0.2.10", "port": null},
  "destination": null,
  "host": {"name": "LAB-WIN-01"},
  "actor": {"name": "synthetic_user", "domain": "LAB"},
  "outcome": "failure",
  "details": {"windows_event_id": 4625},
  "provenance": {"filename": "synthetic-windows.jsonl", "line_number": 1}
}
```

Source and destination endpoint roles must be documented per adapter. Unknown values must remain null rather than being fabricated.

## 4. Timestamp handling

All normalized timestamps must be timezone-aware UTC.

Windows event timestamps must be parsed from explicit timestamp data.

Traditional Linux syslog timestamps may omit year and timezone. Parsing these requires explicit context or must return a controlled error.

The analyzer must not silently guess the year or timezone.

## 5. Cross-source correlation policy

Cross-source event association must not use Zeek UID as a universal identifier.

Candidate associations may use:
- Time-window proximity
- Explicit host identity
- Observed IP addresses
- Account identity when available
- Source-specific identifiers and provenance

Temporal proximity alone is insufficient to establish that two events belong to the same session.

Evidence association must not establish malicious intent.

## 6. Evaluation dataset

Use deterministic, versioned synthetic cases.

Include:
- Matching cross-source evidence
- Unrelated events close in time
- Reused IP addresses
- Missing account identifiers
- Invalid timestamps
- Duplicate events
- Conflicting host identities
- Authorized authentication
- Incomplete telemetry

Define expected associations before running the algorithms.

## 7. Evaluation methodology

Measure:
- Parser correctness
- Rejected malformed records
- Event schema compliance
- Correlation correctness
- False associations
- Missed associations
- Processing errors
- Processing performance

Distinguish failed processing from negative decisions.

## 8. Compatibility requirements

- Preserve the existing V0.6 dataset.
- Preserve R001's documented detection semantics.
- Do not introduce automatic cross-source joins into R001.
- Keep the existing automated regression tests passing.
- Use only synthetic or explicitly authorized security logs.
- Never publish credentials or private operational logs.

## 9. Planned implementation

1. Define schema validation and test fixtures.
2. Implement a Windows Security Event adapter.
3. Implement a Linux SSH authentication adapter.
4. Add controlled cross-source association experiments.
5. Compare association methods and failure cases.
6. Measure processing cost.
7. Publish reproducible experiments and documentation.

## 10. Research limitations

Cross-source correlation may introduce incorrect associations, especially with shared IP addresses, NAT, clock skew, and incomplete identity fields.

Synthetic evaluation does not establish production detection accuracy or prove malicious behavior.
