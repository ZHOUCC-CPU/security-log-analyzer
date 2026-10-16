# V0.9 Research Design: Association Baselines and Robustness

## 1. Research Objective

Evaluate whether explicit endpoint, host-mapping, service,
protocol, port, and timing checks improve candidate evidence
association compared with simpler correlation baselines.

All results describe synthetic activity relationships.
A candidate does not prove a shared session or an attack.

## 2. Frozen V0.8 Baseline

- Commit: c95cac7
- GitHub Actions: CI #11 passed
- Python 3.11 and 3.12: 318 tests each
- Six synthetic labeled pairs
- TP=3, FP=1, TN=2, FN=0
- Precision=75%, Recall=100%, F1=85.71%

Preserve original V0.8 evidence and earlier R001/V0.7 behavior.
Do not change previous labels or reported results.

## 3. Comparison Methods

Baseline A: Time-only association.
Require a Zeek connection and supported host authentication
event within the selected absolute time window.

Baseline B: Source-IP and time association.
Additionally require the Zeek originator IP to match the
remote source IP reported by the host event.

Policy C: Existing V0.8 candidate association.
Apply its endpoint direction, explicit host mapping,
service, protocol, source-port, and timing constraints.

Use identical eligible event pairs and predefined labels
for all three methods. Do not invent missing account data.

## 4. Expanded Synthetic Scenarios

Include controlled positive and negative examples for:

- Windows/Zeek IPv4 relationships
- Linux/Zeek IPv4 and IPv6 relationships
- NAT and shared-address collisions
- Reversed endpoint direction
- Incorrect host-to-IP mapping
- Incompatible destination service ports
- Explicit non-TCP observations
- Conflicting known client source ports
- Missing or uncertain protocol/port evidence
- Time-window boundary and clock-skew cases
- Related activities outside the time window
- Unrelated activities with close timestamps
- Connection without corresponding authentication
- Invalid, duplicate, or conflicting observations

Define relationship labels before running the algorithms.
Do not construct cases solely to improve Policy C scores.

## 5. Evaluation Rules

All methods must use the same clearly defined evaluation
universe, compatible input records, and ground-truth labels.

Report TP, FP, TN, FN, precision, recall, and F1 separately
for every method.

Reject unexpected unlabeled predictions.
Do not silently count invalid records as true negatives.

Keep label files separate from algorithm inputs.

Report false associations and missed associations explicitly.
Do not compare different datasets as production accuracy.

## 6. Sensitivity and Limitations

Evaluate windows of 44, 45, 120, and 121 seconds using
explicitly constructed timing controls.

Study NAT ambiguity, missing evidence, address conflicts,
protocol uncertainty, and known port mismatches.

Document when strict matching prevents a false association
and when it causes a missed related activity.

Synthetic metrics cannot establish real-world attack
detection performance or confirmed session identity.

## 7. Reproducible Evidence

Use a fixed documented seed and deterministic generation.

Preserve source provenance and stable event identifiers.
Keep observations, host mappings, and labels separate.

Export versioned V0.9 JSON/JSONL evidence.
Use UTF-8, LF line endings, and SHA-256 digests.

Require byte-identical regeneration on the same setup.
Do not overwrite archived V0.8 research evidence.

## 8. Acceptance Criteria

1. Review and freeze the experimental design.
2. Write failing TDD tests for the baselines.
3. Implement the independent baseline policies.
4. Generate expanded labeled synthetic scenarios.
5. Evaluate all methods on the same pair universe.
6. Publish counts, metrics, failures, and limitations.
7. Verify evidence hashes and full regression tests.
8. Pass GitHub CI on Python 3.11 and 3.12.

Do not publish incomplete experiments as validated results.
