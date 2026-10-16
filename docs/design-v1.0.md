# V1.0 Research Prototype Release Design

## 1. Release Objective

Deliver a reproducible, explainable, portfolio-ready
defensive security log analysis research prototype.

V1.0 is not a production SIEM, incident-response
platform, or validated attack-detection system.

## 2. Frozen Research Baseline

Preserve V0.3 through V0.9 historical evidence.
V0.9 commit: f0804c2
V0.9 final documentation commit: 672b2f4
GitHub Actions #13: 357 tests passed on Python
3.11 and Python 3.12.

## 3. End-to-End Demonstration

Provide a documented offline demonstration using
versioned synthetic or otherwise authorized evidence.

Show input, normalization, candidate generation,
evidence provenance, output, and limitations.

The demonstration must not claim confirmed attacks
or verified shared authentication sessions.

## 4. Reliability and Input Validation

Test malformed records, missing fields, conflicting
identifiers, invalid mappings, duplicate observations,
unsupported input, and reproducible result ordering.

Retain existing behavior unless a separately tested
and documented correction is justified.

## 5. Controlled Performance Study

Measure execution time and memory on several
documented synthetic dataset sizes.

Separate data generation, association, and reporting
costs when feasible.

Document environment, methodology, repeated trials,
measurement limitations, and observed scaling.

Do not present synthetic throughput as production capacity.

## 6. Documentation and Reproduction

Provide a clear quick start, supported input formats,
example commands, output interpretation, limitations,
test commands, and reproduction instructions.

Keep research conclusions linked to archived evidence.
Avoid exposing sensitive operational log data.

## 7. Release Acceptance Criteria

- End-to-end offline demonstration runs successfully.
- Existing research evidence remains unchanged.
- Robustness and full regression tests pass.
- Performance measurements have documented methods.
- User documentation matches actual behavior.
- GitHub CI passes on Python 3.11 and 3.12.
- Release scope and limitations are clearly stated.

## 8. Release Boundary

Freeze scope after the acceptance criteria are met.

Native EVTX support, broad production ingestion,
real-time alerting, and universal attack classification
are not required for this research-prototype release.

Create a release tag only after final verification
and explicit approval.
