# Research Design

## Research Objective

To investigate the effectiveness and limitations of lightweight, rule-based, multi-source security log analysis.

## Research Questions

### RQ1 - Detection

How accurately can rule-based detection identify predefined suspicious behaviors in labelled security logs?

### RQ2 - Correlation

Can event correlation across different log sources provide additional investigative context compared with individual log analysis?

### RQ3 - Reliability

How do malformed records, missing fields, timestamp differences, and benign activity affect detection reliability?

### RQ4 - Performance

How does processing throughput change as log volume increases?

## Planned Methodology

1. Define a unified security event schema.
2. Implement parsers for selected log formats.
3. Build controlled synthetic datasets.
4. Implement documented detection rules.
5. Develop event correlation logic.
6. Compare expected and observed findings.
7. Evaluate accuracy and performance.
8. Document limitations and reproducibility.

## Evaluation Metrics

- True Positives
- False Positives
- True Negatives
- False Negatives
- Precision
- Recall
- F1-score
- Processing throughput

## Evidence Policy

Experimental results must be supported by reproducible test data and machine-readable outputs.

Synthetic results must be clearly distinguished from results derived from captured laboratory evidence.
