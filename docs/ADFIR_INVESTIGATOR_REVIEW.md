# ADFIR — Phase 2 / Step 19: Investigator Review Subsystem

## Overview
The **Investigator Review** layer introduces the mandatory human-in-the-loop authority downstream of deterministic forensic findings (Step 15) and governed AI reasoning (Step 18). Forensic conclusions and court-admissible decisions are never made autonomously by machines or AI; an authorized human investigator maintains full sovereignty over all accepted facts, inferences, and evidence requests.

---

## Architecture & Lineage Flow

```
Evidence Vault (Immutable Root)
       │
       ▼
Forensic Tool Execution (Step 9) ──► Raw Execution Outputs (Step 10)
                                          │
                                          ▼
                               Structured Artifact Extraction (Step 11)
                                          │
                                          ▼
                               Artifact Normalization (Step 12)
                                          │
                                          ▼
                               Unified UTC Timeline (Step 13)
                                          │
                                          ▼
                               Cross-Domain Correlation (Step 14)
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
                        ┌─────────────────────────────────────┐
                        │   INVESTIGATOR REVIEW (Step 19)    │
                        │   ACCEPT / CHALLENGE / REJECT /     │
                        │   REQUEST_MORE_EVIDENCE             │
                        └─────────────────────────────────────┘
```

---

## Core Invariants

1. **Human Sovereignty**:
   - Neither deterministic rules nor AI reasoning models can establish final legal conclusions without human review.
   - The investigator retains authority to accept, challenge, or reject any claim.

2. **Strict Immutability**:
   - Original deterministic findings and AI reasoning records are **NEVER modified or overwritten**.
   - Investigator decisions are persisted as independent, tamper-detectable `InvestigatorReviewRecord` instances that link to findings or reasoning statements via foreign keys and SHA-256 integrity hashes.

3. **Tamper-Detectable Review Records**:
   - Every review record has a canonical JSON SHA-256 hash computed across review attributes, timestamp, investigator identity, and comments.
   - Database mutations or disk file alterations are immediately detected via the real-time integrity verification endpoint (`GET /api/v1/cases/{case_id}/review/decisions/{review_id}/integrity`).

4. **Controlled Pipeline Re-entry for `REQUEST_MORE_EVIDENCE`**:
   - When an investigator triggers `REQUEST_MORE_EVIDENCE`, no out-of-band execution script is launched.
   - The directive is evaluated against the **Step 17 Governance Gate** to enforce scoping, capability permissions, and safety.
   - If approved, an `AnalysisRequest` is placed in the **Step 8 Resource-Aware Scheduler** queue.
   - The request traverses: Strategy → Capability Selection → Governance → Scheduler → Secure Execution → Outputs → Artifacts → Findings → AI Reasoning → Review.

5. **Multi-Tier Provenance Traceability**:
   - Full lineage trace from a review claim back through structured artifacts, raw tool execution outputs, and source evidence items in the evidence vault.

---

## Supported Investigator Decisions

| Decision | Target Action | Resulting Workflow Action |
| :--- | :--- | :--- |
| `ACCEPT` | Confirms claim as validated forensic evidence | `CLAIM_CONFIRMED_FOR_REPORT` |
| `CHALLENGE` | Flags claim as disputed or requires clarification | `FLAGGED_FOR_CLARIFICATION` |
| `REJECT` | Discards claim due to inconsistency or false positive | `CLAIM_EXCLUDED_FROM_FINDINGS` |
| `REQUEST_MORE_EVIDENCE` | Directs targeted analysis to obtain additional proof | `PIPELINE_REENTRY_QUEUED` |

---

## Database Model & Schema

Table: `investigator_reviews`

```sql
CREATE TABLE investigator_reviews (
    id VARCHAR(36) PRIMARY KEY,
    case_id VARCHAR(36) NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    investigator_id VARCHAR(36) NOT NULL,
    investigator_name VARCHAR(255) NOT NULL,
    target_type VARCHAR(64) NOT NULL,              -- FINDING, AI_REASONING, CLAIM
    target_id VARCHAR(64) NOT NULL,
    statement_id VARCHAR(64),
    decision VARCHAR(64) NOT NULL,                 -- ACCEPT, CHALLENGE, REJECT, REQUEST_MORE_EVIDENCE
    comment TEXT,
    supporting_references JSON DEFAULT '[]',
    resulting_workflow_action VARCHAR(64) NOT NULL,
    action_reference_id VARCHAR(64),
    provenance JSON DEFAULT '{}',
    review_metadata JSON DEFAULT '{}',
    sha256_hash VARCHAR(64) NOT NULL,
    storage_path VARCHAR(1024),
    timestamp DATETIME NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);
```

---

## REST API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/cases/{case_id}/review/items` | Retrieves evidence items, deterministic findings, and classified AI reasoning claims. |
| `POST` | `/api/v1/cases/{case_id}/review/decisions` | Submits an investigator review decision (`ACCEPT`, `CHALLENGE`, `REJECT`). |
| `GET` | `/api/v1/cases/{case_id}/review/decisions` | Lists past review decisions and audit records with optional filters. |
| `GET` | `/api/v1/cases/{case_id}/review/decisions/{review_id}/integrity` | Performs real-time cryptographic verification and tamper detection. |
| `GET` | `/api/v1/cases/{case_id}/review/provenance/{target_id}` | Traces complete multi-tier lineage from claim back to the evidence vault. |
| `POST` | `/api/v1/cases/{case_id}/review/request-more-evidence` | Human directive to request further evidence; re-enters standard pipeline via Governance and Scheduler. |

---

## Verification & Testing Matrix

- **10/10 Unit & Subsystem Tests**:
  - `test_get_review_items_comprehensive`
  - `test_investigator_decision_accept_finding_immutability`
  - `test_investigator_decision_challenge_ai_claim`
  - `test_investigator_decision_reject_claim`
  - `test_request_more_evidence_pipeline_reentry`
  - `test_governance_denial_blocks_request_more_evidence`
  - `test_review_record_cryptographic_integrity_and_tamper_detection`
  - `test_claim_provenance_multi_tier_lineage`
  - `test_case_isolation_and_cross_case_idor_protection`
  - `test_review_history_and_filters`

- **44/44 Combined Subsystem Tests**:
  - Step 16: Specialist Agents (12 tests)
  - Step 17: Governance Gate (13 tests)
  - Step 18: AI Reasoning Layer (9 tests)
  - Step 19: Investigator Review (10 tests)

- **89/89 Regression Tests**:
  - Steps 10–15 (`raw_outputs`, `artifact_extraction`, `artifact_normalization`, `unified_timeline`, `cross_domain_correlation`, `deterministic_findings`)

- **Frontend & Desktop Verification**:
  - `npm run build`: 1890 modules transformed, 0 TypeScript errors.
  - `cargo check`: Finished dev profile in `frontend/src-tauri` with 0 errors.
