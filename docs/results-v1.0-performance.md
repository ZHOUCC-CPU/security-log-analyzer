# V1.0 Controlled Synthetic Performance Study

## 1. Research Objective

Evaluate the in-memory execution time and Python-traced
peak memory of the existing V0.8 Zeek-to-host candidate
association policy at three controlled synthetic scales.

This study does not estimate production performance,
real-world detection accuracy, or attack-detection capability.

## 2. Dataset and Association Scope

- Dataset: V0.9 controlled synthetic event generator.
- Generator seed: `20261011`.
- Scale factors: `1`, `10`, and `50`.
- Events per repetition: 32.
- Explicit host mappings per repetition: 16.
- Association window: 120 seconds.
- Engine: existing V0.8 endpoint-aware candidate policy.
- Candidate interpretation: investigative evidence association.

The benchmark uses normalized in-memory observations.
Ground-truth relationship labels are not supplied to
the association engine.

## 3. Experimental Methodology

For each scale:

1. Generate the deterministic synthetic dataset outside timing.
2. Run one unmeasured association pass as a warm-up.
3. Execute five timed association runs using
   `time.perf_counter_ns()`.
4. Verify identical ordered candidate event-ID pairs
   against the warm-up reference on every timed run.
5. Report the median of the five timing measurements.
6. Run a separate, untimed association pass under
   `tracemalloc` and record its traced peak allocation.

Memory tracing is not active during timed measurements.
The memory measurement consists of one separately traced
association run per scale, not five memory trials.

## 4. Recorded Execution Environment

- Python version: `3.12.11`.
- Operating system family: `Windows`.
- Machine architecture: `AMD64`.
- Logical CPU count reported: `32`.

The report does not record CPU model, CPU frequency,
background workload, or exact operating-system build.
No controlled hardware-to-hardware comparison is made.

## 5. Measured Results

| Events | Mappings | Candidates | Median time (ms) | Traced peak (MiB) |
| ---: | ---: | ---: | ---: | ---: |
| 32 | 16 | 6 | 0.704 | 0.009 |
| 320 | 160 | 60 | 6.964 | 0.161 |
| 1,600 | 800 | 300 | 36.661 | 0.912 |

The displayed values are rounded. The original JSON
contains the individual timing samples and unrounded
numeric measurements.

### Individual timing measurements

| Events | Five timed trials (ms) |
| ---: | --- |
| 32 | 0.717100, 0.704100, 0.695600, 0.695000, 0.726400 |
| 320 | 6.898400, 7.335200, 6.964100, 7.192200, 6.827700 |
| 1,600 | 36.012100, 37.662600, 36.095100, 38.168900, 36.660800 |

## 6. Scaling Interpretation

The largest workload contains 50 times
as many events as the smallest workload.
Its measured median execution time is approximately
52.07 times the smallest median.

These three measurements are consistent with roughly
proportional growth under the selected synthetic workload.
They do not establish formal algorithmic time complexity.

Memory measurements represent Python-traced allocation
peaks during separate association executions.
They are not measurements of full-process RSS.

## 7. Reliability and Evidence Integrity

Every timed run was compared with the warm-up reference
using ordered candidate event-ID pairs.

The independently performed acceptance audit also
verified the expected counts, measurement definitions,
five timing samples per scale, and experiment limitations.

The V0.9 archived evidence was independently verified
unchanged before and after the formal experiment.

## 8. Limitations

- All data are deliberately constructed synthetic observations.
- Only three dataset scales were measured.
- Only one local measurement session was recorded.
- Five timing trials were performed at each scale.
- Only one traced-memory measurement was performed per scale.
- Timing excludes dataset generation, file ingestion,
  JSON reporting, and memory profiling.
- OS scheduling, CPU contention, and background processes
  can influence the results.
- `tracemalloc` does not measure complete process RSS.
- Candidate associations are not confirmed attacks
  or verified shared authentication sessions.
- Results cannot be generalized to enterprise workloads.

## 9. Reproduction and Evidence

Run from the repository root:

```bash
python scripts/benchmark_performance_v10.py --repeats 1 10 50 --trials 5 --window-seconds 120 --output results/benchmark-v1.0-reproduction.json
python -m unittest discover -s tests -q
```

The output path must not exist before execution.
Performance timings may vary between reproductions.
Byte-identical timing reports are not expected.

Original local measurement file:

`results/benchmark-v1.0.json`

SHA-256 of the original measurement JSON:

`f58c0c9e9932f2ef283a1a1f220384f3eb802e12c31013fdeec2b39bcd40687c`

A byte-identical, versioned copy of the measurement
JSON is archived at:

`docs/evidence/v1.0/benchmark-results.json`

The archive manifest is available at:

`docs/evidence/v1.0/manifest.json`

Both archived files use UTF-8 and LF line endings.
The archived measurement JSON preserves the original
SHA-256 shown above.
