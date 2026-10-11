# V0.8 Research Design: Three-Source Evidence Integration

## 1. Research objective

Extend the Security Log Analyzer research prototype to evaluate **candidate evidence associations** among Zeek network observations, selected Windows Security Events, and selected Linux SSH authentication records.

The central question is whether explicit network endpoint, host identity, and timing constraints provide more defensible associations than temporal proximity or shared source IP alone. All outputs remain investigative hypotheses, not proof of a shared session, malicious intent, or successful exploitation.

## 2. Established baseline

- V0.6: Existing Zeek ASCII/JSON ingestion, UID-oriented correlation, R001 trust-boundary detection, evidence assessment, and controlled telemetry/performance experiments.
- V0.7: Unified event schema (`0.7.0`), selected Windows 4624/4625/4672 normalization, limited ISO 8601 SSH authentication normalization, and Windows/Linux candidate associations.
- V0.7 benchmark: 12 synthetic labeled pairs and 24 events; TP=3, FP=2, TN=6, FN=1 at a 120-second window (precision 60%, recall 75%, F1 approximately 66.67%). These figures do **not** estimate real-world attack detection performance.
- Regression baseline: 215 automated tests, green on Python 3.11 and 3.12 under GitHub Actions with Ubuntu 24.04.

## 3. Current integration gap

The existing Zeek parser outputs `event_id`, `timestamp_utc`, `source_type`, `event_type`, `uid`, `source`, `destination`, `provenance`, and `details` but does not produce the V0.7-required `schema_version` or the optional common `host`, `actor`, and `outcome` fields. Its output therefore cannot be passed unchanged through `schema_v07.validate_event`.

V0.8 should introduce a **separate, tested compatibility adapter**, not silently rewrite earlier Zeek research evidence or alter R001's semantics. The V0.7 Windows/Linux evaluator must remain independently reproducible.

## 4. Scope and exclusions

**In scope:**

1. Zeek-to-unified-schema compatibility with explicit missing-field handling.
2. Small, deterministic fixtures representing Zeek network events alongside supported Windows and Linux authentication records.
3. Explicit host-to-address mapping supplied as experiment configuration, with provenance; no inferred mapping from a host name alone.
4. A separate three-source *candidate association* study and negative controls.
5. Parser and correlation robustness tests, controlled comparisons, documentation, and CI regression checks.

**Out of scope for the initial study:**

- Native binary `.evtx` parsing or broad automatic support for all Windows event providers.
- Automatic timezone or year inference for ambiguous legacy syslog timestamps.
- Full enterprise log collection, continuous monitoring, attack attribution, threat scoring, or production SIEM claims.
- Modifying the behavior or published results of R001 and the V0.4–V0.7 experiments.

Real-format input compatibility can be expanded in a **separate optional subphase** after the evidence model is validated. If attempted, start with explicitly documented exported Windows XML/JSON and supported Linux text formats, with controlled fixtures and clear failure reporting.

## 5. Event and evidence representation

- Retain the established V0.7 schema at integration boundaries unless a separately tested schema evolution is justified.
- Preserve original event IDs, Zeek UIDs, timestamps, endpoint roles, raw details, and source-file/line provenance.
- Represent unavailable values with `null`; never invent account names, host addresses, destination ports, or authentication outcomes.
- Treat Zeek `id.orig_h`/`id.orig_p` as the observed network originator and `id.resp_h`/`id.resp_p` as the responder. These network roles are **not** universal user identities.
- A host-authentication record's `source` refers to its reported remote endpoint when present; its destination service/host must come from trustworthy explicit context, not an invented IP.
- Preserve the distinction between an event being observed, an association being suggested, and an activity being malicious.

## 6. Candidate association policy

A three-source candidate may be proposed only under a documented policy that accounts for:

1. **Endpoint roles:** network originator and responder must be compatible with the authenticating client and the receiving host/service.
2. **Host identity:** any host-name-to-IP or interface mapping must be explicitly supplied and auditable.
3. **Time:** timestamps must include explicit timezone information and be comparable in UTC; evaluate boundary and clock-skew conditions.
4. **Evidence type:** distinguish network traffic, Windows login success/failure, Windows privilege assignment, and Linux SSH success/failure. A Zeek connection alone does not establish SSH or Windows authentication.
5. **Provenance and collisions:** repeated IP addresses, NAT, shared accounts, missing fields, duplicate events, reused identifiers, and conflicting records must be handled explicitly.

Do not use a Zeek UID as a universal identifier for Windows or Linux records. Temporal proximity or a shared IP alone must not be described as session identity. Output should carry a cautious interpretation such as `candidate_evidence_association`, with reasons, matched fields, source references, and uncertainty/limitations.

## 7. Research hypotheses and baselines

- **Baseline A:** time-window-only association.
- **Baseline B:** observed-source-IP and time-window association.
- **Baseline C:** V0.7-style source-IP, exact account, and time-window association where those fields are available.
- **V0.8 candidate policy:** explicit endpoint direction, host mapping, event compatibility, and timing, with documented treatment of absent data.

The aim is to compare false associations and missed associations; do not assume that stricter rules always improve overall results. A baseline that lacks applicable fields must be explicitly marked not applicable rather than silently scored as a negative.

## 8. Controlled synthetic scenarios

Define relationship labels *before* executing algorithms. Include at least:

- A compatible network flow and independently recorded host authentication event.
- A related activity with clock skew just inside or outside the chosen window.
- NAT/shared-IP collisions among unrelated clients.
- Shared or reused usernames across unrelated activities.
- Network destination and host mapping disagreements.
- Reversed endpoint direction and unsupported service assumptions.
- Connection without authentication; authentication without network evidence.
- Missing or corrupt source IP, destination IP, event ID, timestamp, and provenance.
- Duplicate observations and conflicting duplicate IDs.
- Authorized activities that match observable behavior but are not malicious.
- IPv4 and IPv6 positive and negative controls.

Use a versioned seed, deterministic case IDs, clear labels, SHA-256 manifests, and LF-formatted UTF-8 evidence files. The evaluation must reject unlabeled predictions instead of treating them as TP or FP by guesswork.

## 9. Evaluation protocol

Measure separately:

- Adapter compliance and parse-error rates.
- Candidate-pair TP, FP, TN, and FN against **predefined synthetic relationships**, together with precision, recall, and F1.
- False-association reasons and missing-evidence behavior.
- Outcome changes under timing, endpoint, NAT, mapping, and identity perturbations.
- Processing time and memory on controlled workloads, clearly distinguishing in-memory benchmarking from ingestion and production throughput.

Compare the V0.8 study to the V0.7 benchmark only when their case definitions, labels, and applicability are made explicit. Never present different synthetic datasets as a head-to-head production accuracy comparison.

## 10. Implementation sequence and acceptance gates

1. **Compatibility contract:** document the precise Zeek-to-V0.7 schema mapping and write tests for preserved fields, missing values, timestamp handling, and input immutability.
2. **Zeek adapter:** implement only the tested compatibility layer; leave the old Zeek parser and R001 behavior unchanged.
3. **Three-source fixtures:** construct deterministic, annotated network/host records with explicit address mappings and known negative controls.
4. **Association engine:** develop a separate module using TDD; report candidate evidence and provenance without asserting sessions or attacks.
5. **Benchmark evaluator:** reject unlabeled predictions and score explicit synthetic relationship labels.
6. **Research artifacts:** publish reproducibility commands, experiment evidence, limitations, and a concise English report.
7. **CI and release:** preserve all 215 existing tests, add targeted new tests, run the complete suite locally and on Python 3.11/3.12 in Ubuntu 24.04, and verify versioned evidence hashes before a GitHub release milestone.

Stop and review each gate before proceeding. Do not commit partial studies as fully evaluated results.

## 11. Validity, security, and responsible use

- Use only synthetic, owned, or explicitly authorized logs; remove or redact operational identifiers and secrets.
- A network connection does not prove host authentication; successful authentication does not prove maliciousness.
- NAT, DHCP, account reuse, clock drift, host-name aliasing, and incomplete logging can create or hide candidate associations.
- Ground-truth synthetic labels describe experiment design, not verified real-world session relationships.
- A positive candidate must remain an investigative hypothesis with traceable evidence, not a confirmed incident.
- No result should be represented as an enterprise deployment benchmark without appropriate real-world evidence and authorization.
