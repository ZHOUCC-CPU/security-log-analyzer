\# V0.3 Validation Report



\## Objective



Validate a lightweight Python-based system for Zeek log parsing, UID-based event correlation, and explainable security detection.



\## Implemented Components



\- V0.1: Zeek ASCII and JSON log parsing

\- V0.2: UID-based connection, NTLM, and Notice correlation

\- V0.3: Rule-based detection with network trust-boundary constraints



\## Automated Tests



\- Parser: 6 tests

\- Correlation engine: 10 tests

\- Detection engine: 12 tests

\- Total: 28 tests, all reported as passing



\## Laboratory Evidence Validation



The system was evaluated with read-only Zeek logs from a previous isolated SMB/NTLM defensive-security experiment.



Observed results:



\- Connection events: 2

\- NTLM authentication events: 1

\- Zeek Notice events: 1

\- Correlated event groups: 2

\- Complete evidence chains: 1

\- Connection-only groups: 1

\- R001 security findings: 1



The correlated evidence used UID `CCpuF7S8CCLEmpKsd`, with a recorded span of 12.834 milliseconds between the connection and Notice timestamps.



\## Detection Rule



R001 detects observed NTLM authentication across a configured network trust boundary when supporting connection and authentication records are correlated.



Findings are classified as requiring investigation rather than confirmed malicious activity.



\## Limitations



The source data comes from one controlled laboratory scenario. It is not an independent production dataset.



The 28 automated tests validate selected software behaviors, not real-world detection accuracy.



No statistically meaningful precision, recall, or false-positive rate has been established.



No Outlook-specific exploitation is claimed.



\## Next Research Phase



Create independently labelled synthetic datasets containing positive, negative, ambiguous, and malformed security events. Evaluate classification performance and processing throughput under documented experimental conditions.
