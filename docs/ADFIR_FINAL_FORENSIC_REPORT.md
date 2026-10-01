# ADFIR — Phase 2 / Step 20: Final Forensic Report Subsystem

## Overview
The **Final Forensic Report** subsystem synthesizes an evidence-grounded, versioned, tamper-detectable, and audit-grade forensic report from the completed investigation. It unifies all 12 phases of the forensic analysis pipeline into a legally defensible forensic artifact without autonomous conclusions, ungrounded speculation, or direct mutation of historical records.

---

## Architecture & Lineage Flow

```
Evidence Vault (Root Immutable Evidence)
       │
       ▼
Forensic Tool Execution (Step 9) ──► Raw Execution Outputs (Step 10)
                                          │
                                          ▼
                               Structured Artifact Extraction (Step 11)
                                          │
                                          ▼
                               Artifact Normalization & Deduplication (Step 12)
                                          │
                                          ▼
                               Unified UTC Timeline (Step 13)
                                          │
                                          ▼
                               Cross-Domain Correlation Engine (Step 14)
                                          │
                                          ▼
                               Deterministic Findings (Step 15)
                                          │
                                          ▼
                               Specialist Agents & Governance Gate (Steps 16–17)
                                          │
                                          ▼
                               AI Reasoning Layer (Step 18: FACT / INFERENCE / UNVERIFIED)
                                          │
                                          ▼
                               Investigator Review & Sovereignty (Step 19)
                                          │
                                          ▼
                        ┌─────────────────────────────────────┐
                        │   FINAL FORENSIC REPORT (Step 20)   │
                        │   12 Forensic Sections, Lineage,    │
                        │   Canonical SHA-256 & Versioning    │
                        └─────────────────────────────────────┘
```

---

## 12 Required Forensic Report Sections

Every synthesized report strictly incorporates and structures the following 12 sections:

1. **Case Information**:
   - Case ID, official case number, case title, description, assigned investigator, and synthesis timestamp.
2. **Evidence Inventory**:
   - Complete itemization of acquired evidence items, evidence types, source file paths, and capture timestamps.
3. **Hashes / Preservation**:
   - Cryptographic SHA-256 hashes of all raw evidence, verification status against disk images, and tamper check confirmations.
4. **Chain of Custody**:
   - Complete, chronological custody events including acquisitions, transfers, checks, and examiner notes.
5. **Tool Executions**:
   - Execution ledger detailing tool names, capabilities, execution status, process exit codes, and timestamps.
6. **Artifacts**:
   - Summary and counts of extracted structured artifacts and normalized forensic entities across all domains.
7. **Timeline**:
   - Chronologically ordered unified UTC events with timestamp sources, certainty levels, and temporal precision windows.
8. **Correlations**:
   - Connected multi-domain correlation groups, correlation types, rule matches, and contributing artifact relationships.
9. **Findings**:
   - Grounded findings and classified claims (`FACT`, `INFERENCE`, `UNVERIFIED`). Every finding links to its supporting evidence and artifact IDs.
10. **Confidence & Verification**:
    - Grounding metrics (percentage of claims verified against physical evidence), overall evidence integrity status, and confidence scores.
11. **Investigator Decisions**:
    - Full record of human investigator reviews (`ACCEPT`, `CHALLENGE`, `REJECT`, `REQUEST_MORE_EVIDENCE`) with rationales and timestamps.
12. **Explainability & Provenance**:
    - Complete multi-tier provenance graph and lineage tracing back to root evidence in the evidence vault.

---

## Core Forensic Invariants

1. **Evidence Grounding**:
   - Every report claim must reference supporting evidence, artifacts, or deterministic findings.
   - Grounding status is strictly evaluated: any claim lacking supporting evidence or artifact lineage is marked `UNVERIFIED` and `is_grounded: False`.
   - Classification labels (`FACT`, `INFERENCE`, `UNVERIFIED`) established in deterministic rules and AI reasoning are immutably preserved.

2. **Strict Immutability**:
   - Raw evidence, forensic executions, extracted artifacts, deterministic findings, AI reasoning, and investigator reviews are never modified.
   - The report operates as a pure synthesis and snapshot layer over immutable forensic primitives.

3. **Cryptographic Integrity & Tamper Detection**:
   - Every report computes a canonical JSON SHA-256 digest (`report_hash` / `sha256_hash`) over its complete 12 sections.
   - Recomputing the canonical digest verifies whether any section has been manipulated in the database or on disk.
   - Real-time verification is available via `GET /api/v1/cases/{case_id}/reports/{report_id}/integrity`.

4. **Multi-Version History**:
   - Sequential versioning (`v1`, `v2`, `v3`, ...) supports case evolution as new evidence is acquired or new findings emerge.
   - Historical snapshots are permanently preserved and individually retrievable.

5. **Multi-Format Court-Ready Exports**:
   - Supports download as formatted, audit-grade Markdown (`.md`) with official verification headers or as machine-readable structured JSON (`.json`).

6. **Case Isolation & RBAC Protection**:
   - Cross-case access is strictly blocked with `403 Forbidden` IDOR protection via `get_authorized_case`.
