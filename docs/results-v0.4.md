# V0.4 Experimental Evaluation Results

## 1. Research Objective

This evaluation investigates the behavior-matching performance and telemetry robustness of a lightweight Zeek-based security log detection and correlation system.

Three detection methods are compared:

- Baseline A: connection records with destination port 445.

- Baseline B: NTLM authentication event presence.

- R001: correlated connection and NTLM evidence with UID, endpoint, timing, and network-boundary validation.

The evaluation does not establish whether observed authentication activity is malicious.

## 2. Experimental Environment

The experiments use deterministic synthetic security events generated with Python.

Dataset configuration:

- Dataset version: 0.4.0

- Random seed: 20261009

- Total cases: 110

- Total events: 210

- Behavior-positive cases: 30

- Behavior-negative cases: 80

- Scenario types: 11

- Cases per scenario: 10

The protected network is `10.10.20.0/24`, and the untrusted network is `10.10.30.0/24`.

Results are evaluated at the synthetic case level.

## 3. Experiment A: Behavior-Matching Evaluation

The first experiment compares all three methods using the same 110 labelled cases.

### 3.1 Confusion Matrix Results

| Method | TP | FP | TN | FN |
| --- | ---: | ---: | ---: | ---: |
| Baseline A | 30 | 70 | 10 | 0 |
| Baseline B | 30 | 70 | 10 | 0 |
| R001 | 30 | 0 | 80 | 0 |

### 3.2 Classification Metrics

| Method | Precision | Recall | F1-score | False Positive Rate |
| --- | ---: | ---: | ---: | ---: |
| Baseline A | 0.3000 | 1.0000 | 0.4615 | 0.8750 |
| Baseline B | 0.3000 | 1.0000 | 0.4615 | 0.8750 |
| R001 | 1.0000 | 1.0000 | 1.0000 | 0.0000 |

### 3.3 Scenario-Level Findings

Baseline A produces positive predictions for connection-only scenarios.

Baseline B produces positive predictions for NTLM-only scenarios.

Both baseline methods produce false positives in six additional behavior-negative scenario categories.

R001 excludes all behavior-negative cases in the current synthetic evaluation.

These results demonstrate correct rule behavior under the selected deterministic scenarios. They do not demonstrate generalization to unknown traffic or attacks.

## 4. Authorized Authentication Analysis

Ten cases in scenario P03 represent authorized cross-boundary NTLM authentication.

All ten are detected by R001.

These cases are behavior-positive because they satisfy the defined network-observable detection conditions.

However, they are not evidence of malicious intent.

Therefore, R001 achieves 100% precision against the current behavior labels while still flagging ten authorized cases.

This distinction is essential when interpreting the operational usefulness of the detector.

## 5. Experiment B: Telemetry Robustness

The second experiment evaluates 30 underlying behavior-positive scenarios under seven telemetry conditions.

A total of 210 case-condition experiments are executed.

### 5.1 Detection Recall

| Condition | Baseline A | Baseline B | R001 |
| --- | ---: | ---: | ---: |
| Original telemetry | 100% | 100% | 100% |
| Missing connection | 0% | 100% | 0% |
| Missing NTLM | 100% | 0% | 0% |
| Missing Notice | 100% | 100% | 100% |
| NTLM UID mismatch | 100% | 100% | 0% |
| NTLM timestamp shifted backward by 60 seconds | 100% | 100% | 0% |
| Reversed input order | 100% | 100% | 100% |

### 5.2 Interpretation

R001 requires corroborating connection and NTLM evidence.

Removing either evidence source prevents a positive detection.

UID mismatches and chronological inconsistencies also prevent detection.

Missing Notice records do not affect R001 detection in the evaluated cases because Notice evidence is optional.

Reversing input record order does not affect detection because correlation is based on event timestamps rather than input ordering.

These outcomes illustrate the trade-off between stricter evidence correlation and sensitivity to incomplete or inconsistent telemetry.

## 6. Label Interpretation

Experiment A evaluates matches against labels describing sufficiently observable behavior.

Experiment B retains the original underlying scenario labels when telemetry is removed or modified.

Consequently, the two experiments measure different properties.

A negative label caused by insufficient observable evidence must not automatically be interpreted as proof that the underlying authentication activity never occurred.

## 7. Automated Verification

The project currently contains 37 passing automated tests:

- Zeek parser: 6

- Correlation engine: 10

- Detection engine: 12

- Robustness experiments: 9

The original synthetic dataset remained unchanged during the robustness experiment.

## 8. Threats to Validity

### Synthetic Data

The dataset uses predefined, deterministic scenarios rather than representative enterprise network traffic.

### Rule-Oriented Scenario Design

Several scenarios directly test conditions encoded in R001. High scores may reflect agreement between the test design and implementation rather than broader detection effectiveness.

### Behavior Versus Intent

The system identifies observable authentication behavior, not whether the activity is authorized or malicious.

### Telemetry Assumptions

Robustness perturbations are deterministic and simplified. Actual telemetry loss, clock drift, event duplication, and ingestion failures may behave differently.

### Baseline Limitations

Baseline methods are deliberately simple. They do not represent mature security detection systems.

### Performance Scope

This version reports classification results and telemetry robustness only. Throughput, memory consumption, and processing latency have not yet been benchmarked.

## 9. Reproducibility

Generate the dataset:

```powershell

python .\\scripts\\generate_dataset.py --seed 20261009 --repeats 10 --output .\\datasets\\synthetic\\v0.4

```

Run the detection benchmark:

```powershell

python .\\scripts\\benchmark_v04.py --dataset .\\datasets\\synthetic\\v0.4 --output .\\results\\benchmark-v0.4.json

```

Run the telemetry robustness experiment:

```powershell

python .\\scripts\\robustness_v04.py --dataset .\\datasets\\synthetic\\v0.4 --output .\\results\\robustness-v0.4.json

```

Run automated tests:

```powershell

python -m unittest discover -s tests -v

```

Generated experiment reports are stored locally under `results/`.

## 10. Conclusion

Under the evaluated synthetic scenarios, R001 provides more selective behavior matching than the two simple baselines.

However, R001 depends on complete and consistent correlation evidence.

The experiments also show that successful behavior matching cannot distinguish authorized authentication from malicious activity.

Future work should evaluate more diverse data distributions, telemetry quality, error handling, processing performance, and evidence-confidence reporting.
