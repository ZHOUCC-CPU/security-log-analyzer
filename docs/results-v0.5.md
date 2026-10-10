# V0.5 Experimental Results: Evidence-Aware Detection Reporting

## 1. Objective and Scope

This experiment evaluates whether an evidence-assessment and explained-reporting layer adds interpretable information to a lightweight Zeek log correlation and detection pipeline **without changing the existing R001 detection decisions**.

The evaluation concerns observable network authentication evidence. Neither a matching detection rule nor a corroborated evidence chain proves malicious activity, successful exploitation, or unauthorized access.

## 2. System Versions and Evaluation Design

The V0.4 pipeline contains a normalized Zeek event parser, UID-based correlation engine, and rule `R001_OUTBOUND_NTLM_TRUST_BOUNDARY`. R001 detects correlated connection and NTLM authentication evidence crossing configured protected and untrusted network boundaries, subject to the implemented endpoint, chronological, and time-window checks.

V0.5 adds two independent components:

- `src/log_analyzer/evidence.py`: assigns an evidence-completeness category and reason codes to correlated UID groups.
- `src/log_analyzer/reporting.py`: enriches existing R001 findings with evidence assessments and retains assessments for UID groups that did not trigger R001.

The comparison is implemented by `scripts/compare_v05.py`. It recomputes the original detection decisions, verifies that the V0.4 case-level predictions and finding UIDs are unchanged, and checks that removing the V0.5 enrichment from each finding restores the original detection report. The experiment uses a fixed synthetic dataset with independent scenario labels; it does not evaluate representative production traffic.

## 3. Dataset and Configuration

| Property | Value |
| --- | --- |
| Dataset | `datasets/synthetic/v0.4/` |
| Dataset type | Deterministic synthetic Zeek-style normalized events |
| Generator seed | `20261009` |
| Scenarios | 11 |
| Cases per scenario | 10 |
| Total cases | 110 |
| Total events | 210 |
| Behavior-positive cases | 30 |
| Behavior-negative cases | 80 |
| Protected network | `10.10.20.0/24` |
| Untrusted network | `10.10.30.0/24` |

A **case** is one independently defined synthetic scenario instance. A **correlated group** is one group of records joined under a UID. These are distinct counting units: the UID-mismatch scenario produces two groups per case.

The generator maintains the case-level behavior and intent annotations separately. The original behavior label is not a claim of maliciousness.

## 4. Evidence Classification Semantics

The V0.5 categories describe the status of *observed evidence*, not threat severity or a probability of compromise:

- **Corroborated:** Connection and NTLM records in the group have a valid UID and satisfy the relevant endpoint, chronological, and correlation-window checks. A Zeek Notice is optional.
- **Partial:** Required connection or NTLM corroboration is absent in the UID group.
- **Conflicting:** Connection and NTLM evidence is present but fails an endpoint, chronological, time-window, or UID-validity check.
- **No relevant evidence:** None of the supported connection, NTLM, or Notice stages is present.

R001 rule matching is independent of this classification: *corroborated* evidence may exist outside the defined network-boundary policy, and *partial* evidence must not automatically be converted into a security alert.

A UID mismatch is **not** automatically repaired or merged across groups. The V0.5 classification does not establish why telemetry was missing and does not resolve the malicious intent of a given authentication event.

## 5. V0.4 versus V0.5 Compatibility Results

The comparison completed successfully for all 110 synthetic cases.

| Compatibility measure | Observed result |
| --- | --- |
| Case-level V0.4 predictions preserved | `true` |
| Original V0.4 finding data preserved | `true` |
| Total R001 findings | 30 |
| Authorized cases flagged by R001 | 10 |

The observed results support the claim that the added evidence-reporting layer does **not** change original R001 decisions **for this evaluated dataset**. They do not prove equivalent behavior for all possible inputs.

## 6. V0.5 Evidence Distribution

### 6.1 All Correlated UID Groups

| Evidence level | Groups |
| --- | ---: |
| Corroborated | 50 |
| Partial | 40 |
| Conflicting | 30 |
| No relevant evidence | 0 |
| **Total** | **120** |

### 6.2 UID Groups Without R001 Findings

| Evidence level | Unalerted groups |
| --- | ---: |
| Corroborated | 20 |
| Partial | 40 |
| Conflicting | 30 |
| No relevant evidence | 0 |
| **Total** | **90** |

The remaining 30 groups are associated with the 30 existing R001 findings and are corroborated in these experiments.

### 6.3 Scenario-Level Interpretation

- **P01, P02, P03:** 30 corroborated groups matching R001, including 10 explicitly authorized cross-boundary authentication cases (P03).
- **N02, N03:** 20 corroborated groups without R001 findings because the observed authentication endpoints fall outside the configured protected-to-untrusted detection policy.
- **N01, N04:** 20 partial groups attributable to connection-only or NTLM-only evidence.
- **N05:** 10 UID-mismatch cases produce 20 independent partial groups; no automatic cross-UID joining is attempted.
- **N06, N07, N08:** 30 conflicting groups due to endpoint inconsistency, reversed event chronology, or exceeding the configured correlation window.

These are scenario-construction results, not estimates of the prevalence of these problems in an operational environment.

## 7. Automated Verification

The user-executed project test suite completed successfully:

```text
Ran 61 tests in 0.118s

OK
```

The V0.5 comparison tests cover preserved predictions, preserved finding data, case and group counts, evidence distributions, scenario-level distributions, and rejection of deliberately altered comparison predictions and dataset hash metadata.

The comparison module additionally checks dataset content checksums via the V0.4 dataset loader. All the above counts and compatibility flags were observed in the reported V0.5 run.

## 8. Reproduction on Windows PowerShell

From the project root:

```powershell
Set-Location "D:\Cybersecurity-Portfolio\security-log-analyzer"

python .\scripts\generate_dataset.py --seed 20261009 --repeats 10 --output .\datasets\synthetic\v0.4
python .\scripts\benchmark_v04.py --dataset .\datasets\synthetic\v0.4 --output .\results\benchmark-v0.4.json
python .\scripts\compare_v05.py --dataset .\datasets\synthetic\v0.4 --previous .\results\benchmark-v0.4.json --output .\results\compare-v0.5.json
python -m unittest discover -s tests -q
```

The generated comparison report is saved to `results/compare-v0.5.json`; files in `results/` are local experiment outputs and may be ignored by Git. The versioned input data and generator remain in the repository.

## 9. Limitations and Threats to Validity

1. **Synthetic, rule-oriented cases:** The scenarios intentionally exercise known conditions in the implemented correlation and detection rules, so the results do not establish generalization to unseen operational telemetry.
2. **Behavior versus intent:** Ten authorized cases still match R001. The evidence assessment is not an authorization check or maliciousness classifier.
3. **Telemetry visibility:** An absent event can mean missing collection, a parsing failure, or that an event never occurred. A partial assessment by itself cannot distinguish these explanations.
4. **UID dependence:** Separate UID groups are not automatically reconciled, reducing the risk of invented correlations but also limiting recovery from UID inconsistencies.
5. **No robustness improvement claim:** V0.5 adds explanation, not a new detection strategy. It does not demonstrate increased recall under missing records or clock skew.
6. **Unalerted explanations:** V0.5 classifies unalerted evidence quality, but it does not yet produce an exhaustive machine-readable explanation for every R001 policy rejection.
7. **Performance unmeasured:** This comparison does not quantify throughput, latency, or memory overhead introduced by evidence reporting.
8. **Version comparison scope:** Invariance was tested for the specified cases and report fields only, rather than formally proven for arbitrary events.

## 10. Conclusion and Next Steps

For the 110-case synthetic evaluation, V0.5 preserved all 30 existing R001 findings and the V0.4 predictions while assigning evidence-quality explanations to 120 UID groups, including 90 that did not trigger R001. Of those 90 unalerted groups, 20 were corroborated, 40 partial, and 30 conflicting.

The result supports a narrow but useful engineering conclusion: **evidence-aware reporting improves observability of non-alerted and conflicting log chains without relaxing the existing security rule in the evaluated cases**.

Future evaluations should introduce separately labelled operational and telemetry-failure conditions, explicit per-rule rejection reasons, quantified performance overhead, and controlled comparisons of any changes to correlation tolerance or detection logic.
