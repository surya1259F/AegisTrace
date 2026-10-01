# ADR-002: Strict Evidence Immutability & Streaming Hashing

## Status: Accepted
## Context
Forensic evidence must remain bit-for-bit identical from ingestion to court testimony. Large files must not cause out-of-memory crashes.
## Decision
All evidence intake computes SHA-256 using 8 MiB streaming reads and forbids write operations.
## Consequences
- Guaranteed preservation of forensic ground truth.
- Constant memory consumption regardless of evidence file size.
