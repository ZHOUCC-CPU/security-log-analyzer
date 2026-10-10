# V0.6 Experimental Results: Telemetry Quality, Endpoint Integrity, and Processing Performance

## 1. Research objective

This study investigates how controlled quality defects in **normalized Zeek-style security events** affect the behavior of a lightweight, rule-based detection pipeline. It addresses two related questions:

1. Can a separate quality-assessment component identify observable record defects without silently changing detection inputs?
2. How do missing or altered records and fields affect rule `R001_OUTBOUND_NTLM_TRUST_BOUNDARY`, and can an identified evidence-integrity failure be reproduced and corrected?
3. How do processing time, throughput, and traced Python allocation peak change with the number of normalized events in a controlled, in-memory pipeline benchmark?

**Interpretation boundary:** R001 reports observable outbound NTLM authentication across configured network boundaries that warrants investigation. A finding does **not** establish malicious intent, an Outlook-specific trigger, exploitation of CVE-2023-23397, or successful compromise.

This report covers **quality, detection impact, and an initial in-memory processing-performance benchmark**. The benchmark was measured after the endpoint-integrity correction; its measurements are not production throughput estimates or full-process memory measurements.

## 2. System and dataset

The evaluated pipeline consists of normalized-event quality assessment (`src/log_analyzer/quality.py`), UID-based correlation (`src/log_analyzer/correlation.py`), and R001 detection (`src/log_analyzer/detection.py`). The rule requires connection and NTLM evidence with compatible endpoints, valid chronological relationships, a maximum correlation span of 300 seconds, and a configured trust-boundary crossing. A Zeek Notice is optional.

| Item | Configuration |
| --- | --- |
| Dataset | `datasets/synthetic/v0.4/` |
| Data provenance | Deterministic, synthetic normalized Zeek-style events |
| Generator seed | `20261009` |
| Scenario repetitions | 10 per scenario, across 11 scenario types |
| Cases / events | 110 / 210 |
| Behavior-positive / behavior-negative cases | 30 / 80 |
| Protected network | `10.10.20.0/24` |
| Untrusted network | `10.10.30.0/24` |
| Correlation time limit | 300 seconds |
| Current local regression result | 100 automated tests passed after adding the performance benchmark tests |
| Published V0.6 quality-stage CI | GitHub Actions run #3: Python 3.11 and 3.12 on Ubuntu both passed (90 tests before the performance additions) |

The 30 positive cases include **10 authorized-authentication cases**. The binary labels represent the dataset's predefined *observable behavior*, **not** a ground-truth classification of malicious activity. The versioned dataset and its SHA-256 manifest were not changed as part of these fault-injection experiments.

## 3. Study design and outcome definitions

### 3.1 Normalized-event quality audit

`assess_event_quality()` examines observed records for duplicate event IDs, absent or unsupported fields, malformed timestamps, missing or invalid endpoint IPs, and invalid ports. It does not repair, discard, or deduplicate input records. Quality issue counts are distinct from the number of affected cases: an event can contain multiple issues.

The unmodified 210-event synthetic dataset produced **210 clean records, zero affected records, and zero recorded issue occurrences**. This is a clean-input sanity check, not evidence that production logs will be complete or valid.

### 3.2 Controlled interventions

Each of the following eight conditions was independently applied to a fresh copy of each eligible case's events:

| Condition | Intervention |
| --- | --- |
| `original` | No change |
| `duplicate_ntlm` | Duplicate an NTLM event, including its event ID |
| `missing_ntlm_uid` | Replace the NTLM UID with null |
| `missing_ntlm_source_ip` | Replace the NTLM source IP with null |
| `invalid_ntlm_source_ip` | Replace the NTLM source IP with `999.999.999.999` |
| `invalid_ntlm_timestamp` | Replace the NTLM timestamp with invalid text |
| `drop_ntlm` | Remove the NTLM event |
| `timestamp_skew_back_60s` | Shift the NTLM timestamp backward 60 seconds |

The quality audit and the correlation/detection pipeline were run separately on each modified case. Processing exceptions were recorded as **processing errors**, not converted into no-alert decisions. An *alert* denotes an R001 finding; a *no-alert* denotes a completed evaluation without one.

### 3.3 Positive and negative subsets

The positive experiment comprised **30 cases × 8 conditions = 240 case-condition runs**. The negative experiment comprised **80 cases × 8 conditions = 640 case-condition slots**. Ten connection-only `N01` cases lack an NTLM record: the seven NTLM-targeting interventions are inapplicable to those cases. Thus the negative study contained **570 evaluated slots and 70 not-applicable slots**, not 640 executed fault injections.

For negative cases, a *new alert versus original* means an R001 alert was observed after intervention when the same case completed without an R001 alert under the unmodified condition. This is a comparison against the original synthetic observation; it is **not** a verified real-world malicious-intent false positive.

## 4. Pre-fix observations

### 4.1 Positive-case outcomes

| Condition | Quality-flagged cases | R001 alerts | No alert | Processing errors |
| --- | ---: | ---: | ---: | ---: |
| Original | 0 | 30 | 0 | 0 |
| Duplicate NTLM | 30 | 30 | 0 | 0 |
| Missing NTLM UID | 30 | 0 | 30 | 0 |
| Missing NTLM source IP | 30 | 30 | 0 | 0 |
| Invalid NTLM source IP | 30 | 0 | 30 | 0 |
| Invalid NTLM timestamp | 30 | 0 | 0 | 30 |
| Dropped NTLM event | 0 | 0 | 30 | 0 |
| NTLM timestamp −60 s | 0 | 0 | 30 | 0 |

The original detector still alerted when a required NTLM source IP was absent. Conversely, absent NTLM records and syntactically valid but reordered timestamps were **not necessarily visible to the record-level quality audit**, although they changed detection outcomes.

### 4.2 Negative-case outcomes

| Condition | Evaluated | Not applicable | Alerts | No alert | Errors | New alerts vs original |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Original | 80 | 0 | 0 | 80 | 0 | 0 |
| Duplicate NTLM | 70 | 10 | 0 | 70 | 0 | 0 |
| Missing NTLM UID | 70 | 10 | 0 | 70 | 0 | 0 |
| Missing NTLM source IP | 70 | 10 | 10 | 60 | 0 | 10 |
| Invalid NTLM source IP | 70 | 10 | 0 | 70 | 0 | 0 |
| Invalid NTLM timestamp | 70 | 10 | 0 | 0 | 70 | 0 |
| Dropped NTLM event | 70 | 10 | 0 | 70 | 0 | 0 |
| NTLM timestamp −60 s | 70 | 10 | 10 | 60 | 0 | 10 |

The 20 induced alerts came from **two distinguishable mechanisms**:

- **N06, missing NTLM source IP (10 cases):** The original connection and NTLM source IPs conflicted. Removing the NTLM IP made the prior correlation logic ignore the missing value and treat the remaining observed endpoint as consistent, producing 10 new alerts. This is a reproducible **evidence-integrity defect**.
- **N08, timestamp −60 s (10 cases):** The original 301-second separation exceeded the configured 300-second window. Shifting NTLM back by 60 seconds reduced the separation to 241 seconds and made the modified evidence satisfy the time-window condition. This is **time-window sensitivity after a data alteration**; it should not be conflated with the missing-endpoint defect or called a confirmed attack false positive.

All 70 evaluated invalid-timestamp negative cases resulted in processing errors. These errors were excluded from no-alert counts.

## 5. Endpoint-integrity correction

### 5.1 Defect and fix

Previously, the correlation engine determined endpoint consistency by counting distinct **non-empty** source and destination IPs in each UID group. This permitted a missing NTLM endpoint to hide a conflict or satisfy the consistency test solely through the connection event.

The V0.6 correction introduces a stricter prerequisite: **each required `zeek.conn` and `zeek.ntlm` record must have non-empty source and destination IP strings** before the group can be considered endpoint-consistent. Existing cross-record consistency checks remain in place. Optional `zeek.notice` events may omit endpoint fields, but supplied conflicting endpoints still affect consistency.

This is an evidence-sufficiency policy change, not a claim of better attack detection. The initial repair specifically targets missing endpoint values; it is not a comprehensive guarantee that every non-empty address is semantically valid or authentic.

### 5.2 Test-driven reproduction

Four targeted regression tests were written before modifying the correlation logic. Before the change, **three failed and one passed**; after the change, **all four passed**:

1. Missing NTLM source IP must not yield an R001 alert.
2. Missing NTLM destination IP must not yield an R001 alert.
3. Removing a conflicting NTLM source IP must not turn a no-alert into an alert.
4. Missing endpoint fields in an optional Notice must not alone suppress an otherwise supported alert.

After adjusting the earlier quality-impact test to reflect the new evidence policy, the quality-stage local suite passed: **90 tests, 0 failures**. That quality-stage implementation and its four experimental archives were committed as `e94b1ad` and successfully tested in GitHub Actions run #3 on Ubuntu with Python 3.11 and 3.12. After adding ten performance-runner regression tests, the local suite passed **100 tests, 0 failures**. GitHub-hosted CI success for these *new performance additions* is **not yet claimed**.

## 6. Pre-fix versus post-fix comparison

The experiments were rerun with the corrected correlation logic, using the same versioned dataset, the same fault conditions, and **new output filenames** so the original evidence was retained.

| Measure | Pre-fix | Post-fix | Interpretation |
| --- | ---: | ---: | --- |
| Original positive cases producing R001 alerts | 30 | 30 | Clean-data behavior preserved in this dataset |
| Positive cases with missing NTLM source IP producing R001 alerts | 30 | 0 | Incomplete required endpoint evidence no longer promoted to alerts |
| N06 negative cases newly alerting after NTLM source IP removal | 10 | 0 | Observed endpoint-integrity defect resolved for the tested cases |
| N08 negative cases newly alerting after −60 s timestamp shift | 10 | 10 | Independent timing sensitivity remains |
| Positive experiment case-condition runs | 240 | 240 | Same controlled design |
| Negative experiment case-condition slots | 640 | 640 | Same controlled design; 570 evaluated and 70 inapplicable per run |

**Trade-off:** The stricter requirement suppresses alerts when NTLM source evidence is missing, including all 30 originally positive synthetic cases under that fault. This reduces unsupported alert promotion, but also reduces alert coverage under telemetry loss. It would be inaccurate to claim an unconditional improvement in detection recall or production accuracy.

The N08 outcome did not change, as expected: moving a timestamp can transform an otherwise out-of-window group into an in-window group without making the timestamp syntactically invalid.

## 7. Reproducibility and preserved evidence

From the repository root, with standard-library Python installed:

```powershell
python -m unittest discover -s tests -q

# Re-run the current (post-fix) positive-case quality-impact experiment.
python .\scripts\quality_impact_v06.py --dataset .\datasets\synthetic\v0.4 --output .\results\quality-impact-v0.6-post-fix-reproduced.json

# Re-run the current (post-fix) negative-case quality-impact experiment.
python .\scripts\quality_negative_v06.py --dataset .\datasets\synthetic\v0.4 --output .\results\quality-negative-v0.6-post-fix-reproduced.json
```

The original pre-fix outputs cannot be regenerated from the corrected code alone without restoring the historical correlation implementation. The following **archived outputs** retain both experimental states:

| Evidence | Repository-relative path |
| --- | --- |
| Positive, pre-fix | `docs/evidence/v0.6/quality-impact-v0.6.json` |
| Negative, pre-fix | `docs/evidence/v0.6/quality-negative-v0.6.json` |
| Positive, post-fix | `docs/evidence/v0.6/quality-impact-v0.6-post-fix.json` |
| Negative, post-fix | `docs/evidence/v0.6/quality-negative-v0.6-post-fix.json` |

These evidence files were copied from locally generated reports without modifying the originals. The raw dataset's integrity is checked by `scripts/benchmark_v04.py` against `datasets/synthetic/v0.4/manifest.json`. These four quality-impact evidence files and the corresponding quality-stage report were committed in `e94b1ad`. The separate performance evidence was archived after that commit; see Section 9 for its pending publication state.

## 8. Limitations and threats to validity

1. **Synthetic design:** These controlled scenarios were constructed around the supported rule and correlation features. The outcomes do not estimate real-world attack detection accuracy, prevalence of log corruption, or enterprise false-positive rates.
2. **Behavior is not intent:** Labels describe observed authentication behavior. The 10 authorized positive cases demonstrate why alert counts must not be interpreted as confirmed attacks.
3. **Input-level quality versus collection loss:** A dropped event may leave no visible sign in the remaining records. This record-level checker cannot establish collection coverage or distinguish “not recorded” from “did not occur.”
4. **Error handling:** The experimental runner distinguishes exceptions from negative decisions, but does not yet implement per-record quarantine or resilient batch processing of malformed records.
5. **Endpoint validation scope:** The endpoint-integrity correction requires non-empty strings for required records, while other IP validation concerns require separate tests and policies. This repair does not authenticate data provenance.
6. **Time synchronization:** A syntactically valid timestamp may be inaccurate. The N08 result illustrates that time skew can change rule matching without triggering the field-quality checker.
7. **Experimental unit:** Case-condition results are repeated interventions on the same underlying fixed scenarios, not independent samples from a population. No inferential confidence intervals or generalization claims are made.
8. **Performance scope:** An in-memory wall-clock and Python-allocation benchmark was measured for three synthetic input sizes, but CPU utilization, disk ingestion, total-process RSS, production log streams, concurrency, and cold-start effects were not evaluated. Three trials at each size do not establish hardware-independent capacity or production scalability.
9. **Validation status:** The quality-stage commit `e94b1ad` passed Ubuntu Python 3.11 and 3.12 CI. The local suite subsequently reached 100 passing tests after performance additions, but the new performance code and expanded report require a new CI run after publication.

## 9. Processing-performance evaluation

### 9.1 Measurement question and scope

The performance experiment investigates whether the *in-memory, sequential* processing time and traced Python memory allocations change predictably as the synthetic dataset scales. The measured pipeline runs three stages in order: normalized-event quality assessment, UID-based event correlation, and R001 detection. The event generator runs **outside** the measured interval. The benchmark does **not** time file loading, Zeek parsing, data generation, network ingestion, or JSON report serialization.

The benchmark script is `scripts/performance_v06.py`, and its measured output is archived in `docs/evidence/v0.6/performance-v0.6.json` (pending the next performance-stage commit). The test runner uses the deterministic `generate(repeats, seed)` function, protected network `10.10.20.0/24`, untrusted network `10.10.30.0/24`, and seed `20261009`.

### 9.2 Measurement environment and procedure

| Parameter | Observed value or procedure |
| --- | --- |
| Operating system | Windows (build and hardware details not independently recorded in this report) |
| Python runtime | CPython 3.12.11 |
| Data source | Deterministic synthetic normalized events, generated in memory |
| Scenario scales | `repeats=10`, `100`, `500` |
| Event counts | 210, 2,100, 10,500 |
| Case counts | 110, 1,100, 5,500 |
| Expected R001 findings | 30, 300, 1,500 |
| Trials | Three sequential trials per scale |
| Timer | `time.perf_counter()`; quality, correlation, and detection timings recorded separately |
| Memory metric | `tracemalloc` traced Python allocation peak during measured processing; input constructed before tracing |
| Other controls | `gc.collect()` before each trial; verifies quality issue count, event count, and R001 finding count |
| Aggregation | Median of the three recorded values for each metric |

`tracemalloc` was enabled **during timing**; its instrumentation overhead is part of the reported elapsed time. The traced peak is **not** the system resident set size (RSS), total process memory, or a peak over the full data-generation and processing lifecycle. No uninstrumented timing comparison or explicit warm-up protocol was included. Stage medians are computed independently and need not sum exactly to the median total.

### 9.3 Observed results

These values were copied from the user-executed `results/performance-v0.6.json` benchmark summary and breakdown. Timing and memory are measured values, not estimates.

| Events | Total elapsed median (ms) | Throughput median (events/s) | Traced allocation peak median (MiB) |
| ---: | ---: | ---: | ---: |
| 210 | 12.5241 | 16,767.672 | 0.183281 |
| 2,100 | 130.1617 | 16,133.778 | 1.801329 |
| 10,500 | 647.9435 | 16,205.117 | 9.018272 |

| Events | Quality median (ms) | Correlation median (ms) | Detection median (ms) | Min total across trials (ms) | Max total across trials (ms) |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 210 | 3.681 | 7.450 | 1.480 | 12.447 | 12.827 |
| 2,100 | 38.920 | 75.787 | 16.010 | 129.160 | 139.447 |
| 10,500 | 190.213 | 383.094 | 72.912 | 629.945 | 657.646 |

At 10,500 events, correlation accounted for approximately **59.1%** of the median total elapsed time (`383.094 / 647.9435`); quality assessment accounted for approximately **29.4%**, and R001 detection for **11.3%**. These are descriptive ratios of independently aggregated medians, not per-trial attribution. Correlation is the largest measured stage in all three scales and the best candidate for targeted profiling before any algorithm changes.

Increasing the input from 210 to 10,500 events multiplies event count by 50 and median total elapsed time by approximately **51.7**; traced Python allocation peaks also increase by about 49.2 times. Throughput stays around **16,100–16,800 events/s** over these measured sizes. These three observations are **consistent with approximately linear scaling within this narrow experimental range**, not proof of asymptotic complexity or general scalability. The number of cases, UID groups, and findings also grows with event count in this generator, so a different event distribution may yield different performance.

### 9.4 Reproduction and integrity

Run from the repository root:

```powershell
python .\scripts\performance_v06.py --scales 10 100 500 --trials 3 --seed 20261009 --output .\results\performance-v0.6.json
python -m unittest discover -s tests -q
```

The archived evidence path is `docs/evidence/v0.6/performance-v0.6.json`. Before preparing this report update, the original and archived file were checked byte-for-byte with SHA-256 and matched:

```text
02A8DF2366EF3AA5647A00C087BC44F2D3634F86022745D9E4E339041450D10E
```

The V0.6 quality-stage GitHub CI verified **90 tests** at commit `e94b1ad`, while the local test suite later passed **100 tests** after the addition of `tests/test_performance_v06.py`. The performance additions and revised report still require a new GitHub CI run. Performance values are environment-dependent: reproducing the *method* is expected; exact timing and peak-allocation values are not guaranteed on a different machine.

### 9.5 Threats to validity and next measurements

The benchmark uses only synthetic normalized events in a single Python process, and it excludes parsing/serialization, disk I/O, network ingest, concurrency, backpressure, end-to-end latency, and operating-system process RSS. With three trials per scale, results support a descriptive baseline rather than uncertainty bounds or production capacity claims. Priority next steps are (a) profile the correlation stage; (b) measure uninstrumented wall-clock time alongside RSS; (c) test larger scales and varied UID/event distributions; and (d) test end-to-end parsing and ingestion, with controlled hardware and runtime metadata.

## 10. Conclusions and next steps

The V0.6 experiments show that the quality audit detects several record-level faults and that telemetry degradation affects R001 in different ways. Ten `N06` negative cases exposed an endpoint-integrity defect, reproduced through failing tests and resolved by requiring non-empty endpoints in the required connection and NTLM records. The repair eliminated the 10 observed induced N06 alerts while leaving detection on clean positive examples unchanged; it also suppressed alerts when required NTLM source evidence was absent in 30 positive cases. This is an explicit evidence-sufficiency trade-off, not an unconditional accuracy gain.

The performance baseline measured 210–10,500 in-memory synthetic events on Windows with Python 3.12.11. The largest input completed in a **647.9435 ms median** with a **16,205.117 events/s median** and a **9.018272 MiB median traced Python allocation peak**. Correlation was the largest time component. The results do not establish production throughput, performance with real enterprise logs, or full-process memory usage.

The quality-stage code, 90-test suite, and four pre-/post-fix evidence files were published in commit `e94b1ad` with successful Ubuntu Python 3.11/3.12 CI. The performance benchmark, its ten new tests (bringing the local total to 100), archived performance output, and this expanded report are prepared for the next commit and CI validation. Further research should strengthen collection-coverage checks, timestamp reliability, endpoint validity, performance instrumentation, and realistic log diversity without conflating incomplete telemetry with malicious intent.
