# V0.8 Phase 2: Three-Source Security Evidence Association Research

## 1. Executive Summary

This study evaluates candidate evidence associations between Zeek network observations and selected Windows Security Event or Linux SSH authentication records.

The study extends the Security Log Analyzer V0.7 research prototype without modifying its original cross-source association logic or the R001 detection rule.

The V0.8 experiment uses six predefined synthetic cases containing twelve normalized security events and six explicit host-to-IP mappings.

At a 120-second correlation window, the experiment produced:

- True positives (TP): 3
- False positives (FP): 1
- True negatives (TN): 2
- False negatives (FN): 0
- Precision: 75.00%
- Recall: 100.00%
- F1 score: 85.71%

The false positive is an intentional NAT/shared-address collision. It demonstrates that matching observable network attributes cannot independently establish that two records describe the same underlying activity.

These results are limited to predefined synthetic activity relationships. They are not estimates of production attack-detection accuracy.

## 2. Research Objective

The primary research question is:

Can explicit network endpoint roles, host-to-address mappings, service compatibility, and timestamp constraints support more defensible candidate associations between network and host authentication evidence?

The study also examines:

1. Whether shared network addresses create false associations.
2. Whether reversed endpoint direction can be rejected.
3. Whether conflicting host mappings can be detected.
4. How protocol and source-port compatibility affect candidate generation.
5. Whether the experimental results are reproducible.

The association engine produces investigative candidates, not confirmed authentication sessions or attack verdicts.

## 3. Sources and Evidence Model

The dataset contains three supported source categories:

- Zeek network connection observations (`zeek.conn`).
- Windows Security Event authentication records (`windows.login_failure`).
- Linux SSH authentication records (`linux.ssh_failure`).

Each candidate joins one Zeek network observation with one compatible Windows or Linux host authentication record.

The term "three-source" describes the supported source categories across the experiment. It does not imply that each candidate contains three log events.

All input events conform to the established normalized schema version `0.7.0`.

The engine preserves source event IDs, available Zeek UIDs, UTC timestamps, endpoint evidence, and independent provenance records.

Windows and Linux authentication adapters do not automatically provide a destination IP address. Destination host addressing is therefore obtained only from explicit experiment-supplied host mappings.

Hostnames are not automatically resolved into addresses.

## 4. Candidate Association Policy

The V0.8 association engine applies the following conditions:

1. A network observation must have event type `zeek.conn`.
2. The host event must represent a failed authentication attempt.
3. The observed network originator must match the reported remote authentication source IP.
4. The Zeek responder IP must match an explicitly provided host mapping.
5. The destination service port must match the supported service context.
6. The absolute timestamp difference must not exceed the configured window.
7. Explicit non-TCP protocol evidence is excluded.
8. If both client source ports are known and nonzero, they must agree.

The initial service-specific policy uses:

- Windows network logon type 3 with TCP destination port 445.
- Linux SSH failed authentication with TCP destination port 22.

These are intentionally narrow experimental compatibility rules, not general models of every Windows or Linux authentication mechanism.

Missing protocol evidence or unavailable source-port information may still permit a candidate association, but must not be interpreted as confirmed protocol or session identity.

The output uses the interpretation `candidate_evidence_association`.

The engine does not receive ground-truth relationship labels.

## 5. Synthetic Dataset Design

The dataset was generated using seed `20261011` and one repetition.

Configuration:

| Property | Value |
|---|---|
| Dataset version | v0.8-phase2 |
| Normalized schema | 0.7.0 |
| Random seed | 20261011 |
| Repetitions | 1 |
| Normalized events | 12 |
| Labeled candidate pairs | 6 |
| Host mappings | 6 |
| Predefined related pairs | 3 |
| Predefined unrelated pairs | 3 |
| Evaluation window | 120 seconds |

The six scenarios are:

| Scenario | Synthetic relationship | Expected purpose |
|---|---|---|
| P01_windows_ipv4 | Related | Windows/Zeek IPv4 positive control |
| P02_linux_ipv4 | Related | Linux/Zeek IPv4 positive control |
| P03_linux_ipv6 | Related | Linux/Zeek IPv6 positive control |
| N01_nat_collision | Unrelated | Shared-address false-association control |
| N02_reversed_direction | Unrelated | Incorrect network endpoint direction |
| N03_wrong_host_mapping | Unrelated | Conflicting destination host mapping |

The experiment defines labels independently of candidate-generation results.

Labels describe simulated activity relationships, not malicious behavior, confirmed exploitation, or real-world session identity.

The NAT collision deliberately resembles a valid positive match in the observable evidence.

## 6. Evaluation Methodology

The evaluator compares produced candidate event pairs against predefined synthetic relationship labels.

Each labeled pair is classified as:

- TP: Related and predicted.
- FP: Unrelated but predicted.
- TN: Unrelated and not predicted.
- FN: Related but not predicted.

Precision, recall, and F1 are calculated from these counts.

Precision is defined as:

Precision = TP / (TP + FP)

Recall is defined as:

Recall = TP / (TP + FN)

F1 is defined as:

F1 = 2 * Precision * Recall / (Precision + Recall)

The evaluator requires all predicted associations to correspond to explicitly labeled pairs.

Unlabeled predictions, invalid event records, duplicate labels, and malformed mappings produce processing errors rather than invented classifications.

The evaluation does not equate absence of a candidate with absence of malicious activity.

## 7. Experimental Results

### 7.1 Confusion Matrix

| Actual relationship | Candidate predicted | No candidate |
|---|---:|---:|
| Related | TP = 3 | FN = 0 |
| Unrelated | FP = 1 | TN = 2 |

Four candidate associations were produced from six labeled pairs.

### 7.2 Metrics

| Metric | Result |
|---|---:|
| Precision | 0.750000 |
| Recall | 1.000000 |
| F1 | 0.857143 |
| Candidate pairs | 4 |
| Labeled pairs | 6 |

The F1 score is rounded to six decimal places in this report.

### 7.3 Per-Scenario Classification

| Scenario | Classification | Predicted |
|---|---|---|
| P01_windows_ipv4 | TP | Yes |
| P02_linux_ipv4 | TP | Yes |
| P03_linux_ipv6 | TP | Yes |
| N01_nat_collision | FP | Yes |
| N02_reversed_direction | TN | No |
| N03_wrong_host_mapping | TN | No |

The results were reproduced using the evaluation script and independently checked against the expected confusion matrix.

## 8. False Association and Sensitivity Analysis

### 8.1 NAT/Shared-Address Collision

The `N01_nat_collision` scenario produced a false positive.

The simulated observations share compatible visible network attributes despite having an explicitly unrelated ground-truth relationship.

This demonstrates a central limitation of log correlation: observable agreement is not sufficient to establish unique activity identity.

The engine reports the pair as a candidate rather than a confirmed incident.

Eliminating this false positive would require additional trustworthy evidence unavailable in the initial experiment.

The reported false association must remain visible in the research results rather than being removed using information from the ground-truth label.

### 8.2 Network Direction and Host Mapping

The reversed-direction case was not associated.

The wrong-host-mapping case was also not associated.

These negative controls show that the implemented endpoint direction and explicit host-mapping restrictions reject the two tested forms of incompatible evidence.

However, these results do not demonstrate that every possible routing, address translation, or host identity ambiguity can be resolved.

### 8.3 Time-Window Sensitivity

The generated paired observations use a 45-second absolute time separation.

At a 120-second window:

- TP = 3
- FP = 1
- TN = 2
- FN = 0

At a 44-second window:

- TP = 0
- FP = 0
- TN = 3
- FN = 3

The shorter window removes the false positive but also misses every predefined related pair.

At a window of exactly 45 seconds, the boundary is inclusive for the tested cases.

This illustrates the precision/recall trade-off and the risk of overinterpreting a single parameter configuration.

### 8.4 Protocol and Source-Port Constraints

Robustness tests verify that explicitly non-TCP observations cannot support the tested TCP-service candidate associations.

Tests also verify that conflicting known, nonzero client source ports prevent a candidate association.

An explicitly recorded TCP protocol is accepted, including supported case and surrounding-whitespace variants.

Missing protocol or source-port evidence remains uncertain rather than being fabricated.

The current policy can still create candidates when protocol evidence is unavailable or when a client source port is unknown.

Source-port equality may be unreliable in environments involving address or port translation.

Therefore, this rule requires further evaluation before broader deployment.

### 8.5 Duplicate Records and Evidence Integrity

The candidate engine rejects conflicting records that share an event ID.

Identical duplicate events do not generate repeated candidate associations.

Conflicting host mappings are rejected rather than silently resolved.

Identical duplicate mappings are accepted without changing the result.

The experimental tests also confirm deterministic output ordering and input immutability for the supported cases.

## 9. Reproducibility and Evidence

All published experimental records are synthetic.

The evidence directory is:

`docs/evidence/v0.8/`

The export contains:

- `events.jsonl`
- `labels.jsonl`
- `host-mappings.jsonl`
- `benchmark-results.json`
- `manifest.json`

The manifest records the dataset configuration, reproduction scripts, record counts, and SHA-256 digests for the four other evidence files.

### 9.1 Verified SHA-256 Values

| Evidence file | SHA-256 |
|---|---|
| events.jsonl | 804e0424638109b93f7245a4b3c464f4aa56d85470c74df417a910dccc67472f |
| labels.jsonl | f57f50394afc70f0b673094aae69f25e796b293665e7b2c65099399b45d205c6 |
| host-mappings.jsonl | ef3d5e7753b394f559eb24acedf73b93ff1a14f1375792f6adde970b4f7e5db8 |
| benchmark-results.json | cfd46a7da72cb40f193bfc4c0ed12a0578400dc3ff96e461ac7b3e966bafeade |

These values were obtained from the locally exported V0.8 evidence files.

All five exported files were checked for UTF-8 encoding and LF line endings.

The manifest is not self-hashed.

The repository's `.gitattributes` configuration includes LF handling for the V0.8 JSON evidence files.

### 9.2 Reproduction Commands

From the repository root:

    python scripts/export_three_source_v08.py

    python -m unittest discover -s tests -q

The export script uses the synthetic seed `20261011`, one repetition, and the default 120-second evaluation window.

The same experiment should be regenerated and its digests checked before claiming cross-environment reproducibility.

### 9.3 Evidence Separation

The evidence exporter keeps observation records separate from the synthetic relationship labels.

The association engine receives normalized events and explicit host mappings.

The evaluator accesses the labels only after candidate generation.

Ground-truth fields are not inserted into the observed event or host-mapping records.

This separation is intended to prevent the engine from using answer labels to manufacture apparently accurate predictions.

## 10. Validation and Compatibility

At the time of this report draft:

- 318 automated tests passed locally.
- The exporter passed ten targeted tests.
- The full regression suite passed.
- Evidence files passed independent SHA-256 checks.
- UTF-8 and LF line endings were verified.
- Identical output across two test directories was verified.
- Repeated dataset generation was tested.
- The existing Zeek/Windows/Linux research modules were not intentionally modified.

GitHub Actions validation of the new V0.8 Phase 2 milestone is pending.

The existing R001 rule and the V0.7 cross-source experiment remain separate from the new candidate association study.

The present study is an extension of the research prototype rather than a replacement for the previously published experiments.

## 11. Limitations and Threats to Validity

This research has several significant limitations:

1. The dataset contains only six labeled pairs and cannot establish generalization.
2. The scenarios are synthetic and may reflect assumptions built into the rules.
3. A NAT/shared-address false positive remains unresolved.
4. Only selected Windows and Linux authentication event types are supported.
5. Host-to-IP mappings are explicitly supplied rather than independently verified in a production environment.
6. Zeek connection observations alone cannot establish that authentication occurred.
7. Missing protocol information reduces certainty.
8. Source-port comparisons can fail when network translation changes observed ports.
9. Clock drift, packet loss, hostname reuse, and incomplete logging may cause false or missed associations.
10. Native Windows EVTX ingestion and broad Linux syslog compatibility are outside the current experiment.
11. Processing throughput, real-world false-alarm rates, and production reliability have not been established.
12. The current service compatibility assumptions cover narrow experimental cases rather than all real authentication traffic.
13. A candidate association does not independently prove that two records describe one authenticated session.
14. The small, deliberately constructed dataset may favor the tested association policy.

The V0.8 synthetic metrics must not be directly compared with V0.7 metrics as if they were measured on the same dataset.

Most importantly, a candidate evidence association does not prove a shared session, malicious intent, exploitation, or attribution.

The reported precision, recall, and F1 must not be represented as operational security detection performance.

## 12. Conclusion and Future Work

The V0.8 experiment demonstrates a reproducible method for studying associations between Zeek network observations and supported Windows/Linux authentication records.

Explicit endpoint direction, service compatibility, and host mapping reject the tested direction and destination conflicts.

The research also demonstrates that a more restrictive candidate association policy does not necessarily resolve ambiguity.

The deliberately constructed NAT collision remains a false association, illustrating the limits of matching visible log fields.

Future work should:

1. Expand positive and negative synthetic controls.
2. Evaluate additional timing and clock-skew uncertainty.
3. Investigate ambiguous and changing host-to-IP mappings.
4. Study source-port behavior under NAT and port translation.
5. Examine protocol uncertainty and incomplete network evidence.
6. Measure execution time and memory on larger controlled datasets.
7. Investigate authorized real-format logs where available.
8. Preserve original evidence and prevent label leakage.
9. Continue validating backward compatibility with existing R001 and V0.7 research.

The prototype remains a defensive research and evidence-analysis tool, not a production security information and event management system.
