# Security Log Analyzer

## Overview

A research-oriented Python project for security log parsing, normalization, threat detection, and cross-source event correlation.

## Research Objective

Design and evaluate a lightweight system capable of detecting and correlating suspicious events across heterogeneous security logs.

## Planned Data Sources

- Zeek network security logs
- Windows Security Event Logs
- Linux authentication logs

## Planned Capabilities

- Structured and unstructured log parsing
- Unified event representation
- Rule-based threat detection
- Multi-event correlation
- Evidence preservation
- Reproducible evaluation

## Evaluation

Detection performance will be evaluated using labelled datasets and documented test procedures.

Planned metrics include precision, recall, F1-score, and processing throughput.

## Research Integrity

All experiments will use authorized or synthetic data.

Planned functionality is not presented as implemented or validated.

## Status

Initial research design and project setup.

## Validated Milestone: V0.3

- Zeek log parsing implemented and tested.
- UID-based event correlation implemented and tested.
- Explainable R001 detection implemented and tested.
- 28 automated unit tests reported passing.
- Real laboratory Zeek logs processed successfully.

See `docs/validation-v0.3.md` for experimental evidence and limitations.
