# V0.4 Detection Evaluation Protocol

## 1. Research Objective

Evaluate the behavior-matching accuracy, limitations, and processing performance of a lightweight security log detection system using reproducible, independently labelled synthetic datasets.

## 2. Evaluation Target

The primary detection target is an observable NTLM authentication event associated with a connection across the configured protected-to-untrusted network boundary.

A positive label does not necessarily indicate malicious intent, unauthorized access, or successful exploitation.

## 3. Compared Methods

- **Baseline A:** TCP/445 connection-based detection.

- **Baseline B:** NTLM event-based detection without trust-boundary correlation.

- **R001:** Correlated connection and NTLM evidence, consistent UID, endpoint validation, chronological constraints, and configured trust boundaries.

All methods will be evaluated against the same labelled cases.

## 4. Dataset Design

The synthetic evaluation dataset will include:

| Case | Scenario | Expected R001 Result |
| --- | --- | --- |
| P01 | Correlated outbound NTLM with Notice | Positive |
| P02 | Correlated outbound NTLM without Notice | Positive |
| N01 | TCP/445 connection without NTLM | Negative |
| N02 | NTLM authentication to an out-of-scope destination | Negative |
| N03 | NTLM authentication from an out-of-scope source | Negative |
| N04 | NTLM event without a corresponding connection | Negative |
| N05 | Connection and NTLM with mismatched UIDs | Negative |
| N06 | Connection and NTLM with conflicting endpoints | Negative |
| N07 | Connection and NTLM with invalid chronological order | Negative |
| N08 | Connection and NTLM exceeding the correlation window | Negative |

Additional authorized cross-boundary authentication cases will be separately annotated to study the distinction between behavior detection and malicious-intent classification.

## 5. Ground Truth

Labels will be defined in the dataset specification before running detection.

Ground-truth labels must not be generated from the detection engine's output.

Each case will retain an independent scenario identifier, expected behavior label, and explanation.

## 6. Evaluation Metrics

- True Positives (TP)

- False Positives (FP)

- True Negatives (TN)

- False Negatives (FN)

- Precision

- Recall

- F1-score

- False Positive Rate

- Processing throughput

Metrics will be reported only where their denominators are defined and nonzero.

## 7. Reproducibility

The evaluation will use fixed random seeds, versioned scenario definitions, documented dataset sizes, and automated verification.

Unit-test fixtures and evaluation datasets will be distinguished.

## 8. Validity and Limitations

Synthetic experiments establish performance only for the evaluated scenarios and distributions.

They cannot establish production detection accuracy or the ability to distinguish legitimate authentication from malicious intent using network evidence alone.

Real laboratory Zeek evidence will be reported separately from synthetic benchmark results.

## 9. Planned Deliverables

- Deterministic synthetic dataset generator

- Machine-readable ground-truth labels

- Baseline detection implementations

- Evaluation runner

- Confusion matrices and metric reports

- Processing performance measurements

- Reproducibility documentation

- Research limitations and error analysis

## 10. Status

Evaluation protocol defined. Dataset generation and quantitative experiments have not yet been completed.
