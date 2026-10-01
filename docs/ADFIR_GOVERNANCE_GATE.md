# ADFIR — Phase 2 / Step 17: Governance Gate Subsystem

## 1. Executive Summary & Objective

The **Governance Gate** constitutes Step 17 of the ADFIR platform. It serves as the authoritative, deterministic policy enforcement and verification checkpoint across the forensic lifecycle. It controls permitted agent reasoning and actions, gates high-risk operations behind explicit human approval workflows, enforces PII and sensitive data handling policies, defends against prompt injection from untrusted evidence, and cryptographically verifies evidence, structured artifacts, and forensic tool outputs.

### Fundamental Safety Controls
1. **Zero Uncontrolled Execution**: No agent may bypass the Governance Gate. Tools may never execute arbitrary shell commands (`shell=True`, metacharacters, or unvalidated parameters are deterministically rejected).
2. **Untrusted Data Isolation**: All forensic evidence, extracted strings, tool outputs, and user-provided inputs are treated strictly as passive **DATA**. Any instruction-like payload (prompt injection, jailbreak pattern, or override directive) is quarantined with a `REVIEW_REQUIRED` decision.
3. **Multi-Point Verification**: Before forensic data is relied upon for correlation or reporting, its cryptographic SHA-256 storage hash, 5-tier lineage chain, tool metadata, and cross-domain consistency (contradiction detection) are deterministically validated.
4. **Explicit Human-in-the-Loop for High-Risk Actions**: Potentially destructive, outward-facing, or sensitive actions require explicit investigator approval (`PENDING` -> `APPROVED` / `REJECTED`).
5. **Court-Ready Auditability**: Every governance evaluation and approval is persisted with SHA-256 integrity hashing and chained into an immutable cryptographic audit log (`GovernanceAuditEvent`).

---

## 2. Governance Gate Architecture & Data Flow

```
                                 [Specialist Agent / User Action]
                                                │
                                                ▼
                                    ┌───────────────────────┐
                                    │    Governance Gate    │
                                    │    (Policy Engine)    │
                                    └───────────┬───────────┘
                                                │
                 ┌──────────────────────────────┼──────────────────────────────┐
                 │                              │                              │
                 ▼                              ▼                              ▼
      [Policy & Safety Checks]       [Untrusted Data Scan]           [Evidence Verification]
      - Agent Capability Gate        - Prompt Injection Defense      - SHA-256 Hash Verification
      - Case Scoping & IDOR          - PII & Secret Redaction        - 5-Tier Lineage Trace
      - Traversal & Shell Metachar   - Passive Data Quarantine       - Contradiction Detection
                 │                              │                              │
                 └──────────────────────────────┼──────────────────────────────┘
                                                │
                                                ▼
                                    ┌───────────────────────┐
                                    │  Governance Decision  │
                                    │  - APPROVED           │
                                    │  - BLOCKED            │
                                    │  - REVIEW_REQUIRED    │
                                    └───────────┬───────────┘
                                                │
                         ┌──────────────────────┴──────────────────────┐
                         ▼                                             ▼
                 [Standard Execution]                         [High-Risk Approval]
                   (Proceeds to Step 7-9)                     (Pending Human Investigator)
```

---

## 3. Data Models & Database Schema

The subsystem introduces three primary SQLAlchemy models in `backend/app/models/models.py`, managed under Alembic migration `016_governance_gate_schema.py`:

### 3.1 `GovernanceDecisionRecord` (`governance_decisions`)
Persists the evaluated outcome for any agent action, tool invocation, or capability request:
- `id`: Unique UUID identifier.
- `case_id`: Scoped forensic case ID (`ForeignKey("cases.id")`).
- `agent_id`: Requesting specialist agent or actor ID.
- `action_type`: Evaluated action (e.g., `CAPABILITY_REQUEST`, `TOOL_EXECUTION`, `EVIDENCE_ACCESS`, `EXPORT_DATA`).
- `target_type` / `target_id`: Entity being acted upon (`EVIDENCE`, `ARTIFACT`, `TOOL`, `CAPABILITY`).
- `risk_level`: Deterministic risk tier (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- `decision`: Evaluated status (`APPROVED`, `BLOCKED`, `REVIEW_REQUIRED`).
- `reason`: Authoritative rationale for the decision.
- `policy_checks`: JSON payload of individual check results (`agent_capability`, `case_authorization`, `tool_safety`, `prompt_injection`, `pii_check`, `high_risk_gate`).
- `approval_status`: Current state (`NOT_REQUIRED`, `PENDING`, `APPROVED`, `REJECTED`).
- `approved_by` / `approved_at`: Investigator identity and UTC timestamp upon approval.
- `rejection_reason`: Mandatory explanation if rejected.
- `sha256_hash`: SHA-256 fingerprint computed across decision inputs.

### 3.2 `EvidenceVerificationRecord` (`evidence_verifications`)
Persists multi-point verification records for evidence, tool outputs, and artifacts:
- `id`: Unique UUID identifier.
- `case_id`: Scoped forensic case ID.
- `target_type`: `EVIDENCE_ITEM`, `EXECUTION_OUTPUT`, `STRUCTURED_ARTIFACT`, `NORMALIZED_ARTIFACT`.
- `target_id`: Identifier of the verified target.
- `verification_status`: `VERIFIED`, `FAILED`, `REVIEW_REQUIRED`.
- `integrity_check`: Detailed hash verification dict (`expected_hash`, `computed_hash`, `tamper_detected`).
- `lineage_check`: 5-tier parent-child lineage verification result.
- `provenance_check`: Verification of associated tool and agent execution provenance.
- `metadata_check`: Tool output and storage metadata validation.
- `contradiction_check`: Cross-domain contradiction scan results (hash collisions, temporal paradoxes).
- `sha256_hash`: Cryptographic checksum of the verification record.

### 3.3 `GovernanceAuditEvent` (`governance_audit_events`)
Provides a tamper-evident audit trail linking all governance decisions:
- `id`: Unique UUID identifier.
- `case_id`: Scoped case ID.
- `decision_id`: Associated `GovernanceDecisionRecord.id`.
- `event_type`: Audit event type (`POLICY_EVALUATION`, `HIGH_RISK_APPROVED`, `HIGH_RISK_REJECTED`, `TAMPER_DETECTED`, `PROMPT_INJECTION_QUARANTINE`).
- `actor_id`: User or agent initiating the event.
- `previous_event_hash`: Cryptographic link to the preceding audit entry for hash-chaining.
- `sha256_hash`: Authoritative SHA-256 block hash computed over event fields and `previous_event_hash`.

---

## 4. Policy Controls & Deterministic Rules

The `GovernanceGateService` (`backend/app/services/governance.py`) enforces strict deterministic policy rules:

### 4.1 Permitted Agent Capabilities
- The requesting agent must exist in the `SpecialistAgentRecord` registry and have `enabled = True`.
- Requested capabilities must explicitly match the agent's configured `approved_capabilities`.
- Actions outside the approved capability set are immediately `BLOCKED`.

### 4.2 Case Authorization & IDOR Protection
- Evaluates requesting user membership and role in `CaseMember`.
- Validates that targeted evidence, executions, outputs, and artifacts belong strictly to the scoped `case_id`. Cross-case access attempts produce HTTP 403/404 errors.

### 4.3 Tool & Parameter Safety
- **Zero Shell Execution**: Flags or configurations requesting `shell=True` are strictly blocked.
- **Dangerous Metacharacters**: Rejects parameters containing shell execution tokens: `;`, `&`, `|`, `` ` ``, `$()`, `>`, `<`, `\n`, `\r`.
- **Path Traversal Protection**: Rejects parameter paths containing directory traversal tokens (`..`, `/etc`, `/var`, `/usr`, `/root`) or pointing outside approved workspace/vault directories.

### 4.4 Untrusted Data & Prompt-Injection Defense
- Inspects textual payloads, command arguments, and artifact strings for prompt-injection markers:
  - System instruction overrides (`ignore previous instructions`, `system prompt`, `you are now`, `developer mode`, `jailbreak`).
  - Command execution attempts embedded in text (`bash -c`, `rm -rf`, `curl http`, `powershell -enc`).
- When detected, the action is marked **`REVIEW_REQUIRED`** with `prompt_injection_detected = True`, and the content is quarantined from automated agent ingestion.

### 4.5 PII & Sensitive Data Detection
- Automatically scans text and metadata for sensitive information:
  - Social Security Numbers (`\b\d{3}-\d{2}-\d{4}\b`).
  - Credit Card Numbers (Luhn-compliant formats).
  - Private Keys (`-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----`).
  - High-entropy API tokens and AWS/GCP access keys.
- Triggers `REVIEW_REQUIRED` or redaction requirement flags for export actions.

---

## 5. Multi-Point Evidence Verification

The `GovernanceGateService.verify_target()` method performs multi-tier forensic verification:

### 5.1 Storage SHA-256 Integrity Verification
- Reads the underlying physical file from the isolated vault or workspace.
- Recomputes the streaming SHA-256 digest and compares it against the recorded `sha256_hash`.
- Any discrepancy immediately sets `verification_status = FAILED`, `tamper_detected = True`, and logs a high-severity audit event.

### 5.2 5-Tier Lineage Verification
- Validates the complete forensic pipeline lineage:
  $$\text{EvidenceItem} \longrightarrow \text{ForensicExecution} \longrightarrow \text{ExecutionOutput} \longrightarrow \text{StructuredArtifact} \longrightarrow \text{NormalizedArtifact}$$
- Verifies that each tier exists, belongs to the same case, and possesses valid hash references matching its parent stage.

### 5.3 Cross-Domain Contradiction Detection
- **Hash Contradictions**: Detects when two normalized artifacts identify the exact same entity identity (e.g., `file:/bin/target.exe`) from the same evidence item but report conflicting cryptographic hashes.
- **Temporal Paradoxes**: Detects event timestamps scheduled in the future relative to case creation and evidence ingestion.
- Discrepancies transition the verification status to `REVIEW_REQUIRED` with contradiction details recorded.

---

## 6. High-Risk Action Approval Workflow

Actions classified as high-risk require explicit authorization by a primary investigator before execution proceeds:

1. **Evaluation**: When an action is evaluated that matches the high-risk registry (`EXPORT_CASE_DATA`, `PURGE_EVIDENCE`, `OVERRIDE_VERIFICATION`, `LIVE_NETWORK_ACQUISITION`), the decision is marked:
   - `decision`: `REVIEW_REQUIRED`
   - `approval_status`: `PENDING`
   - `risk_level`: `HIGH` or `CRITICAL`
2. **Approval**: An authorized investigator submits `POST /api/v1/cases/{case_id}/governance/decisions/{decision_id}/approve`:
   - Decision transitions to `APPROVED`.
   - `approval_status` transitions to `APPROVED`.
   - `approved_by` records investigator ID.
   - Hash-chained audit event `HIGH_RISK_APPROVED` is emitted.
3. **Rejection**: An investigator submits `POST /api/v1/cases/{case_id}/governance/decisions/{decision_id}/reject` with a mandatory reason:
   - Decision transitions to `BLOCKED`.
   - `approval_status` transitions to `REJECTED`.
   - Hash-chained audit event `HIGH_RISK_REJECTED` is emitted.

---

## 7. REST API Reference

All endpoints are mounted under `/api/v1/cases/{case_id}/governance` (with `/api` compatibility aliases) and require standard bearer authentication:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/cases/{case_id}/governance/evaluate` | Evaluate agent action or capability request against governance policies |
| `GET` | `/api/v1/cases/{case_id}/governance/decisions` | List and filter governance decisions (`decision`, `risk_level`, `approval_status`) |
| `GET` | `/api/v1/cases/{case_id}/governance/decisions/{decision_id}` | Retrieve comprehensive decision details, policy checks, and provenance |
| `POST` | `/api/v1/cases/{case_id}/governance/decisions/{decision_id}/approve` | Approve a pending high-risk action (requires investigator role) |
| `POST` | `/api/v1/cases/{case_id}/governance/decisions/{decision_id}/reject` | Reject a pending high-risk action with a documented reason |
| `POST` | `/api/v1/cases/{case_id}/governance/verify` | Verify evidence, execution output, structured artifact, or normalized artifact |
| `GET` | `/api/v1/cases/{case_id}/governance/verifications` | List verification records for the case |
| `GET` | `/api/v1/cases/{case_id}/governance/verifications/{verification_id}` | Retrieve verification record details, lineage, and contradictions |
| `GET` | `/api/v1/cases/{case_id}/governance/audit-trail` | Retrieve the cryptographically chained governance audit trail |

---

## 8. Verification Matrix & Test Coverage

The Governance Gate subsystem is verified by 13 comprehensive integration and security tests in `backend/tests/test_governance_gate_subsystem.py`:

| Test Name | Validated Behavior |
| :--- | :--- |
| `test_governance_policy_allow_standard_action` | Validates standard approved capability requests return `APPROVED` |
| `test_governance_policy_block_unauthorized_agent_or_capability` | Ensures unauthorized or disabled agents and unregistered capabilities are `BLOCKED` |
| `test_governance_policy_block_shell_injection_and_unsafe_parameters` | Confirms rejection of `shell=True`, metacharacters (`;`, `\|`, `$()`), and traversal tokens |
| `test_governance_prompt_injection_and_untrusted_data_quarantine` | Tests detection of instruction overrides in evidence payloads and quarantining |
| `test_governance_pii_and_sensitive_data_detection` | Verifies detection and redaction tagging for SSNs, Credit Cards, and Private Keys |
| `test_governance_high_risk_action_approval_workflow` | Validates `PENDING` -> `APPROVED` / `REJECTED` lifecycle for high-risk operations |
| `test_evidence_integrity_verification_and_tamper_detection` | Validates physical SHA-256 disk re-computation and detection of file tampering |
| `test_artifact_lineage_verification` | Tests 5-tier parent-child lineage verification and detection of broken/orphaned links |
| `test_cross_domain_contradiction_detection` | Validates detection of hash contradictions for matching file paths across sources |
| `test_governance_audit_trail_and_hash_chaining` | Confirms SHA-256 block hash chaining across sequential `GovernanceAuditEvent`s |
| `test_governance_rest_api_full_workflow` | Exercises the complete REST API lifecycle (evaluation, listing, approval, verification) |
| `test_governance_rbac_and_cross_case_idor_protection` | Tests role-based access control and strict cross-case IDOR rejection |
| `test_source_evidence_immutability` | Guarantees that governance evaluations and verifications never alter source evidence |
