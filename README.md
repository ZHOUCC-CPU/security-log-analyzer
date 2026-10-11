# Security Log Analyzer

**A lightweight, research-oriented security log analysis and evidence-correlation prototype built with Python.**

The prototype includes a Zeek-based NTLM trust-boundary detection pipeline and separate V0.7 adapters for selected Windows Security Events and Linux SSH authentication records. V0.7 adds normalized authentication events and a controlled Windows/Linux cross-source candidate-association experiment. The project includes deterministic synthetic datasets, reproducible evaluations, and automated tests.

> **Research scope:** R001 identifies observable Zeek authentication behavior requiring investigation. The separate V0.7 Windows/Linux association rule identifies candidate event co-occurrences, not proven shared sessions or attacks. Neither pipeline establishes malicious intent, exploitation, or production detection accuracy.

## Project status

| Milestone | Implemented and evaluated functionality | Commit |
| --- | --- | --- |
| **V0.3** | Zeek parsing, normalization, UID-based correlation, and the R001 rule; laboratory Zeek log validation | `e392025` |
| **V0.4** | Deterministic labelled synthetic dataset, two simple baselines, classification metrics, and telemetry robustness experiments | `6b28efa` |
| **V0.5** | Evidence-completeness assessment, explained reports, and a regression-checked comparison with V0.4 | `f0d2b0d` |
| **V0.6** | Normalized-event quality assessment, controlled fault injection, endpoint-integrity correction, and synthetic processing performance evaluation | `e94b1ad` (quality phase) |
| **V0.7** | Selected Windows and Linux authentication adapters, normalized event schema, candidate cross-source association, and labeled synthetic benchmark | 978fe78 (CI #7 passed) |

**Current locally verified test result:** 215 automated tests passing locally; GitHub Actions CI #7 passed on Python 3.11 and 3.12.

## Research questions

1. How does UID-based, multi-event correlation compare with simple connection-only and NTLM-only detection under controlled synthetic conditions?
2. How do missing records, UID inconsistencies, and timestamp discrepancies affect detection of underlying authentication scenarios?
3. Can detection output describe evidence completeness and provenance without conflating corroboration with malicious intent?
4. What limitations prevent these laboratory and synthetic findings from being generalized to production environments?

V0.6 includes controlled synthetic processing-performance measurements. V0.7 adds limited Windows/Linux normalization and candidate association. Real-world heterogeneous-log validation, Zeek-to-host correlation, and production-scale evaluation remain future work.

## Implemented functionality

### Zeek parsing and normalization (V0.3)

- Parse Zeek ASCII tab-separated logs and Zeek JSON-line logs.
- Normalize timestamps and selected connection, NTLM, and notice fields.
- Preserve event identifiers and source-file/line provenance.
- Report malformed or inconsistent records rather than silently treating them as valid observations.

### UID-based event correlation (V0.3)

- Group related Zeek events by connection UID without automatically merging different or missing UIDs.
- Check endpoint consistency, event chronology, and a configured correlation time window.
- Distinguish complete, incomplete, and inconsistent event chains.
- Retain evidence references for review.

### R001 detection (V0.3)

`R001_OUTBOUND_NTLM_TRUST_BOUNDARY` identifies qualifying connection-and-NTLM evidence crossing a **configured protected-to-untrusted network boundary**. The rule considers UID correlation, endpoint consistency, event order, and timing. A Zeek notice can support a finding but is not required.

An R001 finding has an investigation-oriented meaning: **it does not establish that the authentication was malicious**. The prototype must not be represented as a full CVE-2023-23397 exploit detector or a production security monitoring system.

### Evidence assessment and explained reports (V0.5)

| Evidence level | Meaning |
| --- | --- |
| `corroborated` | Required connection and NTLM evidence are present and consistent. |
| `partial` | One or more required evidence types are missing within a group. |
| `conflicting` | Present evidence fails consistency, chronology, or time-window checks. |
| `no_relevant_evidence` | No relevant connection, NTLM, or notice evidence is present. |

The explained report attaches evidence assessments to R001 findings and separately retains **unalerted evidence groups**. Evidence quality and trust-boundary policy matching remain independent. No evidence level represents a probability of attack.

### V0.7: Windows/Linux candidate associations

- Validate normalized V0.7 events with explicit UTC timestamps.
- Normalize selected Windows Security Event IDs 4624, 4625 and 4672.
- Normalize a limited set of timezone-aware Linux SSH authentication logs.
- Associate Windows and Linux authentication failures using observed
  source IP, exact username and a configurable time window.
- Preserve provenance and label results as `co-occurrence_only`.
- Reject malformed observations rather than counting them as negatives.
- Keep the Zeek R001 detection pipeline independent and unchanged.

This cross-source experiment does **not** incorporate Zeek events
into its Windows/Linux association rule.

## Architecture

```text
Zeek ASCII / JSON logs
        |
        v
Parse and normalize events
        |
        v
Correlate by Zeek UID
        |
        +--------------------------+
        |                          |
        v                          v
R001 trust-boundary rule   Evidence-completeness assessment
        |                          |
        +-------------+------------+
                      |
                      v
           Explained detection report
           (findings, unalerted groups,
            reason codes, provenance)
```

The diagram above represents the existing Zeek R001 pipeline. The independent V0.7 pipeline normalizes selected Windows/Linux authentication observations, identifies candidate pairs, and evaluates them against synthetic relationship labels. A unified three-source Zeek/Windows/Linux correlation pipeline is not yet implemented.

## Reproduce the experiments

### Requirements

- Python 3 with the standard library; no third-party Python package installation is required for the documented experiments.
- PowerShell examples below assume commands are run from the repository root on Windows. Equivalent arguments can be used in other shells.

Run the complete test suite:

```powershell
python -m unittest discover -s tests -q
```

Generate the **deterministic synthetic** V0.4 dataset:

```powershell
python .\scripts\generate_dataset.py --seed 20261009 --repeats 10 --output .\datasets\synthetic\v0.4
```

Evaluate two baselines and R001 against the labelled cases:

```powershell
python .\scripts\benchmark_v04.py --dataset .\datasets\synthetic\v0.4 --output .\results\benchmark-v0.4.json
```

Evaluate controlled telemetry degradation:

```powershell
python .\scripts\robustness_v04.py --dataset .\datasets\synthetic\v0.4 --output .\results\robustness-v0.4.json
```

Compare V0.5 explained reports with the V0.4 predictions:

```powershell
python .\scripts\compare_v05.py --dataset .\datasets\synthetic\v0.4 --previous .\results\benchmark-v0.4.json --output .\results\compare-v0.5.json
```

Reproduce the **V0.7 synthetic cross-source benchmark**:

```powershell
python .\scripts\export_cross_source_v07.py
```

The command uses seed `20261010`, one repetition and a
120-second association window. It regenerates the versioned
evidence files under `docs/evidence/v0.7/`.

Generated reports under `results/` are deliberately Git-ignored. The versioned dataset and its SHA-256 manifest are in [`datasets/synthetic/v0.4/`](datasets/synthetic/v0.4/).

## Experimental results

### V0.4: Behavior-matching evaluation

The controlled dataset contains **110 synthetic cases / 210 events**, with 30 behavior-positive and 80 behavior-negative cases across 11 scenario types. These labels describe the **defined observable behavior**, not malicious intent.

| Detector | TP | FP | TN | FN | Precision | Recall | F1-score |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Baseline A: TCP/445 connection | 30 | 70 | 10 | 0 | 0.3000 | 1.0000 | 0.4615 |
| Baseline B: NTLM event | 30 | 70 | 10 | 0 | 0.3000 | 1.0000 | 0.4615 |
| R001: correlated evidence | 30 | 0 | 80 | 0 | 1.0000 | 1.0000 | 1.0000 |

**Interpretation:** R001 matched all defined behavior labels in this small, **rule-oriented synthetic** dataset. Its 1.0000 F1-score is **not** an estimate of its ability to detect malicious attacks in real enterprise traffic. **Ten R001-positive cases were explicitly designated as authorized authentication**; these are positive under the *behavior* label but must not be called confirmed attacks.

### V0.4: Telemetry robustness

Thirty underlying behavior-positive cases were each subjected to seven observation conditions (**210 case-condition runs**).

| Condition | Baseline A recall | Baseline B recall | R001 recall |
| --- | ---: | ---: | ---: |
| Original | 100% | 100% | 100% |
| Missing connection | 0% | 100% | 0% |
| Missing NTLM | 100% | 0% | 0% |
| Missing notice | 100% | 100% | 100% |
| NTLM UID mismatch | 100% | 100% | 0% |
| NTLM timestamp shifted backward 60 s | 100% | 100% | 0% |
| Reversed input order | 100% | 100% | 100% |

This is a **controlled positive-case recall study**, not a measurement of production telemetry-failure rates or false-positive behavior under such failures.

### V0.5: Evidence assessment without changing detections

The explained-report comparison processed the same **110 cases**, producing **120 UID evidence groups**, including **30 R001 findings** and **90 unalerted groups**.

| Evidence level | All UID groups | Unalerted groups |
| --- | ---: | ---: |
| Corroborated | 50 | 20 |
| Partial | 40 | 40 |
| Conflicting | 30 | 30 |
| No relevant evidence | 0 | 0 |
| **Total** | **120** | **90** |

The automated comparison confirmed that the **V0.4 predictions and original finding data were preserved**. The difference between 110 cases and 120 groups arises because some cases (such as mismatched-UID scenarios) produce multiple UID groups. This version improves **explainability and auditability**, not measured detection accuracy.

### V0.6: Telemetry quality and processing performance

V0.6 introduces normalized-event quality assessment, controlled telemetry fault injection, stricter endpoint-integrity checks, and a synthetic processing-performance benchmark.

**Telemetry quality experiments**

- 30 behavior-positive cases across eight conditions: 240 case-condition runs.
- 80 behavior-negative cases across eight conditions: 640 case-condition slots, including 570 evaluated and 70 not applicable.
- Missing NTLM source IP initially created 10 new R001 alerts in the N06 negative scenario. After the endpoint-integrity correction, this count decreased to zero.
- The 30 original positive cases continued to produce 30 R001 findings after the correction.
- Timestamp skew still produced 10 new alerts in the N08 negative scenario.

**Synthetic processing performance**

Three trials were performed at each scale on Windows using Python 3.12.11. The reported values are medians.

| Events | Total time (ms) | Throughput (events/s) | Traced peak memory (MiB) |
| ---: | ---: | ---: | ---: |
| 210 | 12.524 | 16,768 | 0.183 |
| 2,100 | 130.162 | 16,134 | 1.801 |
| 10,500 | 647.944 | 16,205 | 9.018 |

Correlation accounted for the largest share of processing time in the measured workload.

**Limitations:** All experiments use controlled synthetic data. Throughput measurements exclude input generation, file ingestion, and networking. Memory figures describe tracemalloc-tracked allocations rather than full-process RSS. These results do not establish production performance or real-world malicious-attack detection accuracy.

See [V0.6 research results](docs/results-v0.6-quality.md) and [archived experimental evidence](docs/evidence/v0.6/).

### V0.7: Synthetic Windows/Linux association study

The fixed-seed experiment includes **24 synthetic events and
12 labeled Windows/Linux pairs**, with four related and eight
unrelated activity-pair labels.

| Measure | Result |
| --- | ---: |
| Association window | 120 seconds |
| Candidate pairs | 5 |
| TP / FP / TN / FN | 3 / 2 / 6 / 1 |
| Precision | 60.00% |
| Recall | 75.00% |
| F1-score | 66.67% |

Two false associations arise from deliberately ambiguous
observed identities in the NAT and shared-account collision
fixtures. One predefined related pair is missed because its
180-second separation exceeds the 120-second window.

**Interpretation:** These are results against predefined
synthetic activity relationships, not validated shared login
sessions, actual attacks or enterprise detection accuracy.
The benchmark uses Windows and Linux observations only;
the separate Zeek R001 pipeline was not modified.

See the [V0.7 research report](docs/results-v0.7-cross-source.md)
and [versioned synthetic evidence](docs/evidence/v0.7/).

Full methodology and interpretations:

- [Research design](docs/research-design.md)
- [V0.3 laboratory validation](docs/validation-v0.3.md)
- [V0.4 evaluation protocol](docs/evaluation-protocol.md)
- [V0.4 results](docs/results-v0.4.md)
- [V0.5 results](docs/results-v0.5.md)
- [V0.7 research design](docs/design-v0.7.md)
- [V0.7 cross-source results](docs/results-v0.7-cross-source.md)

## Repository layout

```text
src/log_analyzer/            Zeek parser, detection and evidence reporting;
                             V0.7 schema, Windows/Linux adapters,
                             and candidate cross-source association
tests/                       Automated regression and integration tests
scripts/                     Dataset generation and experiment runners
datasets/synthetic/v0.4/     Versioned synthetic events, labels, manifest
docs/                        Research design and validated results
results/                     Locally generated reports (Git-ignored)
docs/evidence/v0.7/          Archived synthetic cross-source evidence
```

## Limitations and responsible use

- **Synthetic data is not representative production traffic.** Several scenarios explicitly mirror the rule's conditions; they establish controlled behavior, not generalization.
- **Behavior is not intent.** Authorized NTLM authentication can be flagged; no rule output proves maliciousness or exploitation.
- **Missing evidence is not evidence of safety.** UID mismatches, clock skew, and incomplete logs can prevent correlation.
- **Simple baselines are not mature security products.** Comparative results depend strongly on the selected baselines and case distribution.
- **Heterogeneous support is limited.** V0.7 handles selected structured Windows records and ISO 8601 SSH messages; it does not offer general EVTX/syslog ingestion or a three-source Zeek/Windows/Linux association method.
- **Performance evaluation is limited to controlled synthetic workloads.** The V0.6 benchmark measures in-memory processing on Windows using Python 3.12.11. It does not establish production throughput, real-time ingestion capacity, or total-process memory consumption.
- Use only synthetic, owned, or explicitly authorized security data. Keep credentials, identifiable operational logs, and private datasets out of public commits.

## Planned work

- Expand to additional independently labelled and more diverse datasets.
- Investigate controlled clock-skew tolerance and telemetry gaps while measuring both recall and false-positive trade-offs.
- Add explicit diagnostic reasons for policy non-matches beyond evidence completeness.
- Extend processing-performance evaluation to additional hardware, larger workloads, and full-process memory measurements.
- Extend real-format Windows/Linux compatibility and independently evaluate a separate Zeek integration experiment.

**Project maturity:** Research prototype (V0.7 local study); not a production SIEM or a validated malicious-attack classifier.
