# ADFIR — Phase 2 / Step 18: AI Reasoning Layer Subsystem

## 1. Executive Summary & Objective

The **AI Reasoning Layer** constitutes Step 18 of the ADFIR platform. Positioned downstream of verified forensic structures (Normalized Artifacts, Timeline Events, Cross-Domain Correlations, Deterministic Findings, and the Governance Gate), it delivers governed, evidence-grounded AI synthesis and hypothesis formulation without ever hallucinating facts, fabricating citations, or executing arbitrary code.

### Fundamental Architectural Principles
1. **Governed Upstream Verification**: Reasoning operates exclusively on structured, validated data emitted by Steps 10–17. The Governance Gate evaluates every reasoning request prior to synthesis; requests violating case isolation, attempting direct command execution, or containing injection payloads are blocked or quarantined.
2. **Strict Statement Classification**: Every AI-derived assertion is classified into one of three deterministic categories:
   - `FACT`: Direct observations grounded 1:1 in verified normalized artifacts or timeline events.
   - `INFERENCE`: Correlated deductions supported by multi-domain relationships or deterministic findings.
   - `UNVERIFIED`: Hypotheses or speculative scenarios flagged for investigator validation.
3. **Anti-Hallucination Citation Gate**: Every cited evidence, artifact, finding, or correlation ID is strictly validated against the case database. Any fabricated or cross-case citation is quarantined and rejected.
4. **Secret-Safe External Provider Support**: Optional external LLM provider integration (OpenAI, Anthropic, Gemini, Local) with authenticated HMAC-SHA256 encrypted credential storage at rest. API keys are never logged, never returned in API payloads (masked), and never passed into model prompts.
5. **Deterministic Stateless Fallback**: If an external LLM is not configured, disabled, or fails, the subsystem seamlessly switches to a rule-based deterministic reasoning engine without breaking the forensic pipeline.
6. **Zero Raw Evidence Egress**: Raw forensic disk images, byte streams, and secure vault paths are strictly blocked from external transmission by default.

---

## 2. System Architecture & Information Flow

```
   ┌────────────────────────────────────────────────────────────────────────┐
   │            Verified Structured Forensic Context (Steps 10-15)          │
   │   - Normalized Artifacts   - Timeline Events   - Correlations         │
   │   - Deterministic Findings - Lineage Hash      - Provenance            │
   └───────────────────────────────────┬────────────────────────────────────┘
                                       │
                                       ▼
   ┌────────────────────────────────────────────────────────────────────────┐
   │                     Step 17: Governance Gate                           │
   │   - Case Scoping / IDOR Protection                                     │
   │   - Prompt Injection Detection & Quarantine                            │
   │   - High-Risk Parameter Sanitation                                     │
   │   - Block / Review / Approve Decision                                  │
   └───────────────────────────────────┬────────────────────────────────────┘
                                       │ APPROVED
                                       ▼
   ┌────────────────────────────────────────────────────────────────────────┐
   │                     Step 18: AI Reasoning Service                      │
   │  ┌──────────────────────────────────────────────────────────────────┐  │
   │  │ Context Sanitizer: Strips vault paths, raw bytes & disk paths     │  │
   │  └────────────────────────────────┬─────────────────────────────────┘  │
   │                                   │                                    │
   │         ┌─────────────────────────┴─────────────────────────┐          │
   │         ▼                                                   ▼          │
   │  [External LLM Adapter]                         [Deterministic Fallback]│
   │  (OpenAI / Anthropic / Gemini / Local)          (Rule-based Synthesizer)│
   │         │                                                   │          │
   │         └─────────────────────────┬─────────────────────────┘          │
   │                                   │                                    │
   │  ┌────────────────────────────────▼─────────────────────────────────┐  │
   │  │ Anti-Hallucination Citation Gate: Validates all cited entity IDs │  │
   │  └────────────────────────────────┬─────────────────────────────────┘  │
   │                                   │                                    │
   │  ┌────────────────────────────────▼─────────────────────────────────┐  │
   │  │ Output Classifier: FACT / INFERENCE / UNVERIFIED Tagging         │  │
   │  └────────────────────────────────┬─────────────────────────────────┘  │
   │                                   │                                    │
   │  ┌────────────────────────────────▼─────────────────────────────────┐  │
   │  │ SHA-256 Canonical Integrity Hashing & Audit Chaining             │  │
   │  └──────────────────────────────────────────────────────────────────┘  │
   └───────────────────────────────────┬────────────────────────────────────┘
                                       │
                                       ▼
   ┌────────────────────────────────────────────────────────────────────────┐
   │               Persistent AI Reasoning Record & REST APIs               │
   │   - /api/v1/cases/{case_id}/ai/reason                                  │
   │   - /api/v1/cases/{case_id}/ai/reasoning/{id}                          │
   │   - /api/v1/cases/{case_id}/ai/reasoning/{id}/integrity                │
   │   - /api/v1/cases/{case_id}/ai/reasoning/{id}/provenance               │
   └────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Database Models & Schema Migration

Managed under Alembic migration `017_ai_reasoning_layer_schema.py`:

### 3.1 `AIProviderConfigRecord` (`ai_provider_configs`)
Stores user-configured external LLM parameters:
- `id`: Unique UUID identifier.
- `case_id`: Scoped case ID (nullable for user-global default).
- `user_id`: Owning investigator user ID.
- `provider`: Provider ID (`openai`, `anthropic`, `gemini`, `local`).
- `model`: Target model name (e.g. `gpt-4o`, `claude-3-5-sonnet`, `gemini-1.5-pro`).
- `endpoint`: Optional custom API endpoint URL (HTTPS enforced for external).
- `api_key_encrypted`: Authenticated HMAC-SHA256 ciphertext keystream pad.
- `api_key_masked`: Masked display representation (`sk-****1234`).
- `is_enabled`: Boolean activation toggle.
- `status`: Connection status (`ACTIVE`, `DISABLED`, `ERROR`).
- `last_tested_at`: UTC timestamp of latest connection test.

### 3.2 `AIReasoningRecord` (`ai_reasoning_records`)
Persists immutable, auditable reasoning outputs:
- `id`: Unique UUID identifier.
- `case_id`: Scoped case ID.
- `request_user_id`: Initiating investigator ID.
- `governance_decision_id`: Upstream Step 17 Governance Gate approval link.
- `objective`: Investigation reasoning goal.
- `status`: Lifecycle status (`COMPLETED`, `BLOCKED`, `FAILED`).
- `execution_mode`: `EXTERNAL_LLM` or `DETERMINISTIC_FALLBACK`.
- `provider`: Provider name used.
- `model`: Model name used.
- `input_references`: JSON dictionary of input IDs (`finding_ids`, `artifact_ids`, etc.).
- `raw_evidence_egress_blocked`: Enforces raw evidence containment.
- `egress_approved`: Boolean flag indicating investigator authorization.
- `statements`: Structured JSON list of classified statements (`AIStatementItem`).
- `citations_verified`: Boolean confirming anti-hallucination verification.
- `summary`: High-level forensic summary.
- `provenance`: End-to-end lineage mapping.
- `reasoning_metadata`: Execution metrics, injection detection flags, citation counts.
- `sha256_hash`: Canonical cryptographic integrity hash over all statements and metadata.
- `created_at` / `completed_at`: Precise UTC timestamps.

---

## 4. Key Services & Security Implementation

### 4.1 Authenticated Cryptographic Credential Management
`backend/app/services/ai_reasoning.py` implements authenticated encryption without third-party dependencies:
- Random 16-byte initialization vector (`os.urandom(16)`).
- SHA-256 derived keystream mask XOR pad.
- HMAC-SHA256 authentication tag over IV and ciphertext with constant-time verification (`hmac.compare_digest`).
- Plaintext API keys are zeroized from local memory and never included in audit records, error traces, or API responses.

### 4.2 Sanitized Forensic Context Builder
`AIReasoningService.build_reasoning_context`:
- Extracts case-scoped deterministic findings, normalized artifacts, timeline events, and cross-domain correlations.
- Recursively strips vault paths, raw filesystem paths, binary byte sequences, and storage paths.
- Evaluates untrusted data payloads against prompt-injection and instruction-override heuristics (`PROMPT_INJECTION_PATTERNS`).

### 4.3 Anti-Hallucination Citation Gate
`AIReasoningService._verify_statement_citations`:
- Inspects every ID referenced in `supporting_evidence_ids`, `supporting_artifact_ids`, `supporting_finding_ids`, and `supporting_correlation_ids`.
- Validates membership in the authorized context set (`valid_art_ids`, `valid_ev_ids`, etc.).
- Strips hallucinated or cross-case citations and quarantines ungrounded statements as `UNVERIFIED`.

### 4.4 Cryptographic Tamper Verification
`AIReasoningService.verify_integrity`:
- Canonical JSON reconstruction over `case_id`, `objective`, `execution_mode`, `provider`, `model`, `governance_decision_id`, and `statements`.
- SHA-256 digest comparison against `rec.sha256_hash`.
- Accurately detects manual modification, statement insertion, or database tampering.

---

## 5. REST API Endpoints

Mounted under `/api/v1` and `/cases/{case_id}/ai`:

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/provider/config` | Configure external LLM provider credentials |
| `GET` | `/api/v1/provider/config` | Retrieve current provider config (masked credentials) |
| `DELETE` | `/api/v1/provider/config` | Remove provider configuration |
| `GET` | `/api/v1/provider/status` | Check provider configuration status |
| `POST` | `/api/v1/provider/test-connection` | Verify network connection to LLM provider |
| `POST` | `/api/v1/cases/{case_id}/ai/reason` | Execute governed AI reasoning over case data |
| `GET` | `/api/v1/cases/{case_id}/ai/reasoning` | List reasoning records for case |
| `GET` | `/api/v1/cases/{case_id}/ai/reasoning/{id}` | Retrieve specific reasoning record |
| `GET` | `/api/v1/cases/{case_id}/ai/reasoning/{id}/integrity` | Verify SHA-256 integrity and detect tampering |
| `GET` | `/api/v1/cases/{case_id}/ai/reasoning/{id}/provenance` | Inspect 7-tier provenance and Governance link |

---

## 6. Verification & Quality Matrix

| Test Suite | Tests | Result | Focus |
|---|---|---|---|
| **Step 18 AI Reasoning Subsystem** | 9 | **9 / 9 PASSED** | Classification (`FACT`/`INFERENCE`/`UNVERIFIED`), Anti-Hallucination, Secret Protection, Fallback, Tamper Detection, IDOR |
| **Step 17 Governance Gate Subsystem** | 13 | **13 / 13 PASSED** | Policy Gates, Prompt Injection Defense, PII Detection, High-Risk Approvals, Lineage |
| **Existing AI Provider & Copilot Tests** | 64 | **64 / 64 PASSED** | Provider adapters, Copilot context, HTTPS enforcement, credential hygiene, audit logs |
| **Step 16 Specialist Agent Subsystem** | 12 | **12 / 12 PASSED** | 11 Specialist Agents, Capability Request Gate, Lifecycle, IDOR |
| **Steps 10–15 Phase 2 Regression** | 89 | **89 / 89 PASSED** | Raw outputs, extraction, normalization, timeline, correlation, deterministic findings |
| **Frontend Production Build** | — | **SUCCESS** | Vite + TypeScript compile (`tsc -b && vite build`) |
| **Tauri Desktop Engine Check** | — | **SUCCESS** | Rust backend integration (`cargo check`) |
