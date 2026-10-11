# V0.7 Research Report: Cross-Source Authentication Event Association

**Project:** Security Log Analyzer
**Version:** V0.7 — controlled cross-source association study
**Evidence basis:** Deterministic synthetic Windows/Linux event pairs
**Status:** Local experiment reproduced; GitHub CI verification for this uncommitted V0.7 study remains pending

## 1. Executive Summary

V0.7 extends the Security Log Analyzer research prototype with a normalized event schema, Windows Security Event and Linux SSH authentication adapters, and a candidate association method for authentication failures observed in both sources. The existing Zeek-oriented detection pipeline and V0.6 R001 rule remain separate and unchanged.

The cross-source experiment evaluates whether simple, observable criteria—matching source IP, exactly matching account name, and an absolute event-time difference of at most 120 seconds—can recover *predefined synthetic activity relationships*. It does **not** evaluate actual attack detection, establish session identity, or demonstrate production reliability.

In the initial fixed-seed benchmark, 24 normalized synthetic events form 12 labeled Windows/Linux pairs (4 labeled related; 8 labeled unrelated). The rule generated five candidate pairs: **3 true positives, 2 false positives, 6 true negatives, and 1 false negative**, giving **precision 0.6000, recall 0.7500, and F1-score approximately 0.6667**. The two false positives are deliberate collision cases; the false negative involves a related pair separated by 180 seconds.

## 2. Scope and Research Questions

The experiment addresses three questions:

1. Can a deterministic correlation rule associate synthetically related Windows and Linux failed-authentication observations under a fixed time window?
2. Under what deliberately controlled conditions does matching on IP, username, and time produce an association even though the pair is labeled unrelated?
3. What relevant relationships are missed when the time-window constraint is too narrow?

The benchmark is **Windows/Linux only**. Although V0.7 also defines V0.7-formatted Zeek event types, this particular cross-source algorithm compares `windows.login_failure` with `linux.ssh_failure`; it does not join Zeek records or revise the V0.6 R001 detection semantics.

## 3. Implementation and Evidence Model

### 3.1 Normalized event representation

The V0.7 schema uses `schema_version`, `event_id`, `timestamp_utc`, `source_type`, `event_type`, and `provenance`, alongside optional source/destination endpoint, host, actor, outcome, UID, and details fields. Invalid schema records are rejected rather than silently treated as negative observations. Timestamps must represent UTC with explicit time-zone information.

The Windows adapter handles structured representations of Security Event IDs 4624 (successful logon), 4625 (failed logon), and 4672 (special privileges assigned to a logon). Event 4672 is not treated as independent proof of a newly successful logon or of malicious activity. The Linux adapter handles a deliberately limited family of `sshd[PID]` authentication messages with explicitly time-zoned ISO 8601 timestamps. These adapters are research prototypes; their accepted formats should not be described as covering all real-world Windows or Linux logging variants.

### 3.2 Candidate association rule

A candidate is emitted only when both records are valid V0.7 events and all of the following conditions are met:

- One is a Windows failed-logon observation; the other is a Linux failed-SSH-authentication observation.
- Both outcomes are `failure`.
- Their observed source IP addresses match after IP-address canonicalization.
- Their observed usernames match **exactly**, including case.
- The absolute UTC timestamp difference is at most **120 seconds** (inclusive).

Missing source endpoints or account names prevent association. The rule excludes unspecified IPs, multicast IPs, and the limited IPv4 broadcast address `255.255.255.255` as single-client source identifiers. Exact duplicate events are deduplicated; conflicting contents with the same event ID generate a processing error. The result has the explicit interpretation `co-occurrence_only` and retains source provenance. Matching criteria do not prove that two events share a login session, user, device, operator, or malicious objective.

## 4. Synthetic Dataset Design

The generator `scripts/generate_cross_source_v07.py` constructs 12 deterministic labeled cases at `seed=20261010`, `repeats=1`. Each case contributes one Windows event and one Linux event, giving 24 events and 12 candidate pair labels. Four pairs are labeled related and eight unrelated. Labels are specified by the scenario generator independently of the correlation engine's predictions, and are not included in the event records presented to the engine.

Case time slots are separated to prevent accidental cross-case matching within the 120-second window. Test/benchmark ranges are used for the synthetic addresses; the scenario labeled as multicast intentionally uses a multicast source value to test filtering. These fixtures are designed to exercise individual decisions, **not** sampled from an operational environment.

| Scenario | Synthetic relationship label | Predicted candidate at 120 s | Classification | Experimental purpose |
|---|---|---|---|---|
| `P01_shared_activity` | Related | Yes | TP | Matching failed-authentication observations |
| `P02_ipv6_shared_activity` | Related | Yes | TP | Equivalent rule behavior with IPv6 source |
| `P03_time_boundary` | Related | Yes | TP | Exactly 120-second boundary is included |
| `P04_delayed_related_activity` | Related | No | FN | Related activity 180 seconds apart |
| `N01_different_ip` | Unrelated | No | TN | Different observed source IP |
| `N02_different_username` | Unrelated | No | TN | Different observed account names |
| `N03_unrelated_outside_window` | Unrelated | No | TN | Outside the configured time window |
| `N04_nat_collision` | Unrelated | Yes | FP | Shared visible IP and account despite separate synthetic relationship label |
| `N05_shared_account_collision` | Unrelated | Yes | FP | Reused visible account/IP characteristics despite separate synthetic relationship label |
| `N06_missing_endpoint` | Unrelated | No | TN | Missing source endpoint prevents association |
| `N07_success_not_failure` | Unrelated | No | TN | Successful Windows logon excluded from failure-only rule |
| `N08_multicast_source` | Unrelated | No | TN | Multicast source excluded as a client identity |

**Fixture interpretation note:** N04 and N05 are *collision proxies*. The generator does not reproduce a real NAT gateway or account-sharing infrastructure, nor does it encode independently observable activity-group identifiers for the engine. They have deliberately indistinguishable relevant matching characteristics and different scenario labels. Their failure demonstrates the rule's ambiguity under such conditions; it does not quantify real NAT-related false associations.

## 5. Evaluation Protocol

The evaluator `scripts/evaluate_cross_source_v07.py` runs the association engine on the event records **without labels**. It then compares each unordered predicted event pair against the fixed label inventory. Predictions without a corresponding label produce an error instead of being arbitrarily counted as TP or FP. Duplicate labels, unknown event references, and malformed inputs are also rejected.

Definitions, relative to **synthetic related/unrelated pair labels**:

- **TP:** Labeled related, predicted associated.
- **FP:** Labeled unrelated, predicted associated.
- **TN:** Labeled unrelated, not predicted associated.
- **FN:** Labeled related, not predicted associated.

Precision = TP / (TP + FP). Recall = TP / (TP + FN). F1 = 2 × Precision × Recall / (Precision + Recall). Invalid records are processing errors, not true negatives. The evaluation set consists of the 12 explicitly labeled pairs; it is not an exhaustive, independently labeled collection of every conceivable event pair.

## 6. Measured Results

The local exported run reported:

| Quantity | Observed |
|---|---:|
| Synthetic normalized events | 24 |
| Labeled Windows/Linux pairs | 12 |
| Positive (`related=True`) labels | 4 |
| Negative (`related=False`) labels | 8 |
| Association window | 120 seconds |
| Predicted candidate pairs | 5 |
| True positives | 3 |
| False positives | 2 |
| True negatives | 6 |
| False negatives | 1 |
| Precision | 0.6000 (60.00%) |
| Recall | 0.7500 (75.00%) |
| F1-score | ~0.6667 (66.67%) |

The confusion matrix below uses the synthetic pair label as the reference:

| | Predicted associated | Predicted not associated |
|---|---:|---:|
| **Labeled related** | TP = 3 | FN = 1 |
| **Labeled unrelated** | FP = 2 | TN = 6 |

These values exactly describe this small deterministic fixture under the given evaluation configuration. They are **not** estimates of enterprise detection accuracy, population precision/recall, or real malicious-activity rates. No statistical confidence interval or generalization claim is supported by a 12-case constructed benchmark.

## 7. Failure Analysis and Implications

### 7.1 False associations: visible-identity collisions

The `N04_nat_collision` and `N05_shared_account_collision` cases were labeled unrelated even though the observed IP, username, event type, and timestamp proximity satisfy the rule. Both therefore became false-positive *associations*. This is evidence that the chosen features do not uniquely identify an activity. A shared egress address, reused account identifier, NAT, proxying, logging artifacts, or independent uses of the same credentials can make superficially related records appear connected.

No attack label is involved. These FP outcomes are mistakes against **predefined synthetic activity relationships**, not false attack alerts. Without stronger, defensible linking evidence (for example, a reliable session or device identifier shared across sources), the appropriate wording remains **candidate co-occurrence**.

### 7.2 Missed association: fixed window

`P04_delayed_related_activity` is labeled related but its events are separated by 180 seconds. Because 180 > 120, the baseline rule produces no candidate and the evaluation records one FN. Expanding the window might recover this pair but would also admit more chance coincidences. This is an explicit precision–recall trade-off to test in later controlled window-sensitivity experiments; it has not yet been measured here.

### 7.3 Evidence quality and safe rejection

The engine refuses to correlate missing or ambiguous source/actor fields and filters invalid single-client source identifiers such as multicast, unspecified, and limited-broadcast addresses. Conflicting event identities and invalid normalized records generate explicit processing errors rather than being counted as negative evidence. It also leaves original event dictionaries unmodified, enabling reproducible downstream comparisons.

## 8. Reproducibility and Integrity

### 8.1 Environment and commands

From the repository root, the evaluation can be reproduced with Python and the project source tree:

```powershell
python -m unittest discover -s tests -q
python .\scripts\export_cross_source_v07.py
```

At the time of the local report, **215 automated tests passed**. Cloud GitHub Actions validation of this newly generated V0.7 evidence and benchmark code was **not yet performed**; it should be reported after committing and observing the CI workflow for that commit. The export uses `seed=20261010`, `repeats=1`, and `window_seconds=120`.

### 8.2 Versioned evidence artifacts

The exporter creates these files in `docs/evidence/v0.7/`:

| File | Size in verified local run | SHA-256 |
|---|---:|---|
| `events.jsonl` | 10,264 bytes | `bc91fec168499d79a610d857b658f24afbab0d8194c6a0a96d4102779d792ef9` |
| `labels.jsonl` | 1,602 bytes | `3ed2581ba9d867b32abbc16a45aee98cf285062f5ad3c2730319b839eecb6b60` |
| `benchmark-results.json` | 3,456 bytes | `dfba927168d561c9ef2dbe28b9079c7637ee3236ed6e81d49306ca0ba56d4fc2` |
| `manifest.json` | 1,016 bytes | `5d11fcbcc7a1bec8040bd78da1f235cad8c14455218e9dcf62722e69304c7487` |

The manifest embeds checksums for the first three files; its own checksum above is an externally recorded checksum. The local validation compared each embedded checksum with its file, checked event/label counts (24/12), and confirmed LF-only bytes for all four files. `.gitattributes` specifies `text eol=lf` for each evidence path to reduce Windows/Linux line-ending drift. The integrity results establish byte consistency for this export; they do not establish external data authenticity because the inputs are generated synthetic records.

## 9. Threats to Validity and Research Limitations

1. **Small, constructed sample.** Exactly 12 hand-specified scenario families are evaluated at one seed/repetition. The measured scores are not representative of operational prevalence or deployment performance.
2. **Ground-truth interpretation.** `related` means the dataset designer stipulated an activity relationship. It does not indicate a confirmed common authentication session, malicious operator, or successful exploit.
3. **Limited distinctiveness of collision fixtures.** N04/N05 encode ambiguous observable features but do not model NAT behavior or credential-sharing processes in a realistic network.
4. **Only Windows and Linux are cross-correlated.** Zeek support in the broader repository must not be conflated with evaluation of a three-source association method.
5. **Restricted adapter formats.** Structured Windows Security events and a subset of time-zoned ISO 8601 `sshd` lines are supported; vendor/export variations, locale differences, real syslog time-context problems, and field quality issues need separate validation.
6. **Shared IP does not establish device identity.** Address reuse, NAT, VPNs, proxies, and collection topology can invalidate naïve identity assumptions. Username string equality likewise does not guarantee principal identity across hosts/domains.
7. **Event timing uncertainty.** The rule uses observed timestamps and an absolute window; clock skew, ingestion delay, collection latency, and imperfect time synchronization were not comprehensively evaluated in this benchmark.
8. **No production or attack efficacy claim.** The algorithm yields candidates, not attack verdicts. No enterprise SIEM comparison, live-traffic study, external validation, production throughput estimate, or maliciousness classifier evaluation is provided.
9. **Potential pair explosion.** The initial algorithm groups by observed IP and username, then compares qualifying Windows/Linux events within a group. Very large groups may produce many event pairs; this experiment has not quantified scaling under such collisions.

## 10. Next Research Steps

1. Test association-window sensitivity (e.g., shorter, baseline, and longer windows) on an unchanged labeled dataset and report the trade-offs without changing labels after observing predictions.
2. Add controlled cases for timestamp skew, missing actor identities, case differences, duplicated/replayed events, and denser many-to-many collision groups.
3. Evaluate processing time and memory across increased event counts, especially large shared-IP/shared-account buckets.
4. Compare safer *investigative grouping* and higher-evidence association strategies, while keeping confidence and provenance explicit and avoiding claims of shared sessions.
5. Design a **separate** Zeek integration experiment with an explicit mapping of field semantics, host identities, and independent labels; do not assume Zeek UID is a universal cross-source ID.
6. After review, commit the evidence and report, check GitHub CI on Python 3.11/3.12, and update the README with the exact synthetic-only scope.

## 11. Conclusion

The V0.7 prototype demonstrates a reproducible way to normalize selected Windows and Linux authentication observations and find candidate cross-source co-occurrences. Its initial synthetic benchmark reveals both correct matches and deliberately exposed failure modes: **two false associations** from ambiguous observed identities and **one missed association** from a fixed time window. These results motivate conservative interpretation, stronger provenance handling, and carefully scoped future experiments. The principal finding is a limitation of observable-field correlation, **not** a validated ability to identify attacks in real environments.
