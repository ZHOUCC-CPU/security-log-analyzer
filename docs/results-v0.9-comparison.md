# V0.9: Controlled Comparison of Security Evidence Association Methods

## 1. Executive Summary

This study compares three Zeek-to-host authentication evidence
association methods on the same 16 predefined synthetic cases.

The evaluated methods are time-only association, source-IP-plus-time
association, and the existing V0.8 endpoint-aware policy.

At a 120-second window, the results were:

| Method | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| A: Time only | 7 | 8 | 0 | 1 | 46.67% | 87.50% | 60.87% |
| B: IP and time | 6 | 6 | 2 | 2 | 50.00% | 75.00% | 60.00% |
| C: V0.8 policy | 5 | 1 | 7 | 3 | 83.33% | 62.50% | 71.43% |

The endpoint-aware policy produced fewer false associations but
missed more predefined related activities.

These measurements describe deliberately constructed synthetic
relationships. They do not measure production attack detection.

## 2. Research Question and Scope

The primary research question is:

How does adding source-IP, endpoint direction, explicit host
mapping, service, protocol, and client-port constraints change
false and missed evidence associations?

The study extends the V0.8 Phase 2 research without replacing
its candidate association engine or earlier R001/V0.7 behavior.

The term "three-source" refers to the supported source categories
across the study: Zeek, Windows, and Linux. Each labeled pair
contains one Zeek observation and one Windows or Linux event.

An association is an investigative candidate, not proof of a
shared session, authentication outcome, attack, or attribution.

## 3. Methods and Information Available

Method A: Time-only baseline.

A supported Zeek connection and host authentication failure are
associated when their absolute UTC timestamp difference is within
the configured window.

Method B: Source-IP-plus-time baseline.

Method B adds equality between the Zeek originator IP and the
remote source IP in the host event.

Method C: Existing V0.8 candidate policy.

Method C uses source IP, endpoint direction, explicit host-to-IP
mapping, supported service destination port, time window,
protocol compatibility, and available client source-port evidence.

The V0.8 policy requires Windows network logon type 3 with
service port 445, or Linux SSH failure with service port 22.

Explicit non-TCP observations are rejected. Conflicting known
nonzero client ports are also rejected. Unknown client ports may
still permit a candidate.

All three methods use the same eligible event categories and
the same evaluation window. Method C deliberately uses additional
mapping and service evidence unavailable to the simpler baselines.

None of the association methods receives ground-truth labels.

## 4. Synthetic Dataset and Design

The V0.9 dataset contains:

| Property | Value |
|---|---|
| Dataset version | v0.9 |
| Normalized event schema | 0.7.0 |
| Generator seed | 20261011 |
| Repetitions | 1 |
| Events | 32 |
| Explicit host mappings | 16 |
| Labeled pairs | 16 |
| Related pairs | 8 |
| Unrelated pairs | 8 |
| Primary evaluation window | 120 seconds |

The original six V0.8 scenario records are preserved as the
initial dataset prefix. Ten additional controlled scenarios
examine timing, missing fields, incompatible service evidence,
source-port uncertainty, and addressing conflicts.

Relationship labels are fixed independently of predictions.

A positive label means that the simulated activities are defined
as related. It does not imply that the records establish a
verified shared session or malicious activity.

A negative label means that the simulated activities are defined
as unrelated, even if visible log attributes appear compatible.

## 5. Evaluation Methodology

Each labeled pair is classified as:

- TP: Related and predicted as a candidate.
- FP: Unrelated but predicted as a candidate.
- TN: Unrelated and not predicted.
- FN: Related but not predicted.

Precision = TP / (TP + FP)

Recall = TP / (TP + FN)

F1 = 2 * TP / (2 * TP + FP + FN)

All methods are scored against the same 16 labeled pairs.

The evaluator rejects duplicate predictions and predictions
outside the explicitly labeled universe. Invalid input and
unlabeled results are not silently counted as true negatives.

The evaluation universe is a controlled set of predefined pairs,
not every possible pair in a production log stream.

## 6. Experimental Results

### 6.1 Confusion Matrices and Metrics

| Metric | A: Time only | B: IP and time | C: V0.8 policy |
|---|---:|---:|---:|
| True positives | 7 | 6 | 5 |
| False positives | 8 | 6 | 1 |
| True negatives | 0 | 2 | 7 |
| False negatives | 1 | 2 | 3 |
| Candidate pairs | 15 | 12 | 6 |
| Precision | 0.466667 | 0.500000 | 0.833333 |
| Recall | 0.875000 | 0.750000 | 0.625000 |
| F1 | 0.608696 | 0.600000 | 0.714286 |

Metrics are shown to six decimal places.

### 6.2 Per-Scenario Classification

| Scenario | A | B | C |
|---|---|---|---|
| P01_windows_ipv4 | TP | TP | TP |
| P02_linux_ipv4 | TP | TP | TP |
| P03_linux_ipv6 | TP | TP | TP |
| N01_nat_collision | FP | FP | FP |
| N02_reversed_direction | FP | TN | TN |
| N03_wrong_host_mapping | FP | FP | TN |
| P04_boundary_120 | TP | TP | TP |
| P05_outside_120 | FN | FN | FN |
| P06_unknown_client_port | TP | TP | TP |
| P07_port_translation | TP | TP | FN |
| P08_missing_zeek_source_ip | TP | FN | FN |
| N04_wrong_service_port | FP | FP | TN |
| N05_udp_protocol | FP | FP | TN |
| N06_wrong_client_port | FP | FP | TN |
| N07_source_ip_mismatch | FP | TN | TN |
| N08_ipv6_host_mapping_conflict | FP | FP | TN |

All rows describe predefined synthetic relationship controls.

## 7. False Association Analysis

Method A produces eight false associations because temporal
proximity alone does not establish an activity relationship.

Method B rejects the reversed-direction and source-IP mismatch
controls but cannot resolve destination host mapping errors,
service incompatibilities, or source-port conflicts.

Method C rejects seven of the eight unrelated controls.

However, the N01_nat_collision case remains a false association
under all three methods. Compatible visible attributes do not
necessarily identify the same underlying activity when network
addresses are shared or translated.

The results do not establish that all possible NAT ambiguity can
be detected or eliminated.

## 8. Missed Association Analysis

Three controls illustrate why stricter matching may reduce recall.

P05_outside_120 is a predefined related pair separated by
121 seconds. All methods miss it at the 120-second window.

P07_port_translation simulates related activity where the two
records expose different known client source ports. Method C
rejects the candidate, while Methods A and B retain it.

P08_missing_zeek_source_ip represents an incomplete network
observation. Method A retains the time-based candidate, while
Methods B and C cannot satisfy their source-IP requirement.

These cases illustrate policy trade-offs. They do not validate
a specific production NAT topology, clock-drift distribution,
or missing-log frequency.

## 9. Timing Sensitivity

The experiment includes 45-second original controls and new
explicit boundaries at 120 and 121 seconds.

At a 44-second evaluation window, all 16 labeled pairs are
unmatched by each method in the tested dataset.

At 120 seconds, P04_boundary_120 is included, while
P05_outside_120 is excluded.

At 121 seconds, P05 becomes eligible by time:

| Method | TP | FP | TN | FN |
|---|---:|---:|---:|---:|
| A: Time only | 8 | 8 | 0 | 0 |
| B: IP and time | 7 | 6 | 2 | 1 |
| C: V0.8 policy | 6 | 1 | 7 | 2 |

These controlled boundaries demonstrate inclusive window
behavior, not operational clock synchronization accuracy.

## 10. Reproducibility and Validation

Evidence is stored in:

`docs/evidence/v0.9/`

The exported files are:

- `events.jsonl`
- `labels.jsonl`
- `host-mappings.jsonl`
- `benchmark-results.json`
- `manifest.json`

The manifest records seed, dataset sizes, evaluation settings,
reproduction paths, and SHA-256 hashes of the four data files.

The manifest does not contain its own hash.

Verified SHA-256 digests:

| File | SHA-256 |
|---|---|
| events.jsonl | 3d8bb09858df155afb0f3156ebde02500b6f889251d6ed08543c755fea40458d |
| labels.jsonl | 0ac2079ad02fdae8121fcfb4fd67e1e21a100e690f45c9751b5e1c412d8c5487 |
| host-mappings.jsonl | f2f6eec86748adccdc850c558bc0e537f9f7507b26044d886ecd7379eab6d875 |
| benchmark-results.json | f1efab7c29aa25d3eedd35f87f92c6d92dcc7ad22bf9c8c0d95c3efed93ff0b7 |

All five files passed UTF-8, LF, and byte-identical
regeneration checks.

The V0.7 and V0.8 archived evidence files were checked and
remained unchanged.

From the repository root, reproduction commands are:

    python scripts/export_comparison_v09.py

    python -m unittest discover -s tests -q

The export command writes the default v0.9 evidence directory.
Use a separate output directory to compare regenerated bytes
without overwriting the archived copy.

At the time of this report:

- 357 automated tests passed locally.
- All eight V0.9 exporter tests passed.
- Three method-specific confusion matrices were verified.
- Repeated synthetic generation was tested.
- GitHub Actions CI #12 passed all 357 tests on both Python 3.11 and 3.12.

## 11. Limitations and Threats to Validity

The study has important limitations.

1. Only 16 labeled pairs were evaluated.
2. All scenarios are synthetic and deliberately constructed.
3. The dataset is not representative of real network traffic.
4. The label universe excludes unlabeled cross-case combinations.
5. The policy has access to richer evidence than the baselines.
6. NAT/shared-address ambiguity remains unresolved.
7. Exact source-port matching can miss translated connections.
8. Missing source IP information can prevent useful association.
9. The time-window experiment does not model real clock drift.
10. Host mappings are explicitly supplied, not independently trusted.
11. Supported Windows/Linux authentication types are restricted.
12. Runtime scalability and resource usage were not measured here.
13. Real-format data validation is not included in this milestone.
14. A candidate association is not a verified shared session.
15. No attack-detection or production false-alarm rate is established.

The balanced synthetic cases do not represent operational base
rates. Therefore, measured precision is especially sensitive to
the experimental sampling design.

This experiment must not be described as demonstrating production
detection accuracy or proving that one method is universally best.

## 12. Conclusion and Future Work

On the same 16 predefined synthetic pairs, the full V0.8
policy reduced false associations relative to time-only and
IP-plus-time baselines.

This improvement was accompanied by additional missed related
activities under port translation and incomplete evidence.

The central research finding is a measurable precision/recall
trade-off in a restricted, reproducible synthetic setting.

Future work should evaluate more independently designed cases,
clock uncertainty, address translation, incomplete logging,
controlled processing performance, and authorized real-format
evidence where available.

The Security Log Analyzer remains a defensive research prototype,
not a production SIEM or verified attack-detection system.
