# ADFIR — Phase 2 / Step 16: Specialist Agent Layer Subsystem

## 1. Executive Summary & Objective

The **Specialist Agent Layer** represents Step 16 of the ADFIR platform. It establishes a strictly controlled, evidence-grounded forensic agent framework where 11 domain-specialized agents analyze normalized artifacts, timeline events, correlations, and deterministic findings.

Forensic agents in ADFIR operate under fundamental safety constraints:
1. **Zero Direct Execution**: Agents never execute subprocesses directly or construct arbitrary shell commands.
2. **Capability Request Gate**: All forensic collection or specialized tool execution must be requested through the Step 7 Forensic Capability Registry, passing through Step 8 Resource-Aware Scheduling, Step 9 Secure Execution, and Step 10+ artifact extraction pipelines.
3. **Strict Evidence Grounding**: Agents never speculate, fabricate evidence, or declare adversary intent. Every claim or observation must cite verifiable normalized artifact IDs or evidence IDs.
4. **End-to-End Auditability & Integrity**: Cryptographic SHA-256 hashing, hash-chained lifecycle audits, 7-tier provenance tracing, and POSIX-isolated storage ensure court-ready defensibility.

---

## 2. The 11 Specialist Forensic Agents

ADFIR registers and provisions 11 persistent, versioned specialist agents in the database (`SpecialistAgentRecord`), each configured with designated evidence domains, supported artifact types, capabilities, and safety permission profiles:

| Agent Name | Agent ID | Agent Type | Primary Domains | Supported Artifact Types | Approved Capabilities |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Investigation Strategy Agent** | `agent-investigation-strategy` | `STRATEGY` | STRATEGY, PLANNING, MULTI_DOMAIN, CASE | EVIDENCE, FINDING, ARTIFACT, CORRELATION, TIMELINE_EVENT | `investigation_planning`, `evidence_triage`, `capability_sequencing`, `case_assessment` |
| **Disk Forensics Agent** | `agent-disk-forensics` | `DISK` | DISK, FILESYSTEM, PARTITION, STORAGE | FILE_ENTRY, DELETED_FILE, DIRECTORY, MFT_RECORD, INODE | `fls_filesystem_listing`, `deleted_file_recovery`, `partition_analysis`, `FILESYSTEM_ANALYSIS`, `DELETED_FILE_CARVING` |
| **Memory Forensics Agent** | `agent-memory-forensics` | `MEMORY` | MEMORY, VOLATILITY, PROCESS, NETWORK | PROCESS, THREAD, HANDLE, NETWORK_CONNECTION, INJECTION, DLL, KERNEL_MODULE | `process_listing`, `network_scan`, `dll_list`, `malfind_injection`, `MEMORY_ANALYSIS`, `PROCESS_ANALYSIS` |
| **Malware Analysis Agent** | `agent-malware-analysis` | `MALWARE` | MALWARE, SIGNATURE, STATIC_ANALYSIS, BINARY | MALWARE_HIT, YARA_HIT, HASH, STRING_EXTRACT, SIGNATURE_MATCH, PE_METADATA | `yara_scanning`, `file_hashing`, `string_extraction`, `STATIC_MALWARE_ANALYSIS`, `YARA_RULE_SCAN` |
| **Windows Forensics Agent** | `agent-windows-forensics` | `WINDOWS` | WINDOWS, LOGS, REGISTRY, SYSTEM | EVENT_LOG, EVTX, REGISTRY, PREFETCH, AMCACHE, SHIMCACHE, SRUM, LNK, JUMPLIST, DEFENDER_ALERT | `evtx_analysis`, `registry_analysis`, `prefetch_analysis`, `amcache_analysis`, `WINDOWS_EVTX_ANALYSIS` |
| **Browser Forensics Agent** | `agent-browser-forensics` | `BROWSER` | BROWSER, WEB, NETWORK, DOWNLOADS | BROWSER_HISTORY, DOWNLOAD, COOKIE, CACHE_ENTRY, SESSION_STORE, FORM_DATA | `browser_history_analysis`, `download_audit`, `cookie_inspection`, `BROWSER_HISTORY_ANALYSIS` |
| **Linux Forensics Agent** | `agent-linux-forensics` | `LINUX` | LINUX, LOGS, AUTH, SYSTEMD, SHELL, CRON | AUTH_LOG, SYSLOG, JOURNALD, BASH_HISTORY, SHELL_HISTORY, CRON_JOB, SYSTEMD_SERVICE | `auth_log_analysis`, `journal_analysis`, `shell_history_audit`, `cron_audit`, `LINUX_LOG_ANALYSIS` |
| **Network Forensics Agent** | `agent-network-forensics` | `NETWORK` | NETWORK, PCAP, FLOW, DNS, HTTP, TLS | PACKET, NETWORK_FLOW, DNS_QUERY, HTTP_REQUEST, TLS_HANDSHAKE, IP_ENDPOINT | `packet_dissection`, `dns_lookup_analysis`, `flow_reconstruction`, `PCAP_PACKET_DISSECTION` |
| **Timeline / Correlation Agent** | `agent-timeline-correlation` | `CORRELATION` | TIMELINE, CORRELATION, CROSS_DOMAIN, TEMPORAL | TIMELINE_EVENT, ARTIFACT_RELATIONSHIP, CORRELATION_GROUP, TEMPORAL_WINDOW | `entity_correlation`, `temporal_alignment`, `provenance_graph`, `cluster_analysis`, `TIMELINE_CORRELATION` |
| **Evidence Verification Agent** | `agent-evidence-verification` | `VERIFICATION` | INTEGRITY, PROVENANCE, CUSTODY, VERIFICATION | EVIDENCE_ITEM, RAW_OUTPUT, STRUCTURED_ARTIFACT, HASH_RECORD, PROVENANCE_CHAIN | `hash_verification`, `chain_of_custody_audit`, `tamper_detection`, `PROVENANCE_AUDIT` |
| **Report / Summary Agent** | `agent-report-summary` | `REPORT` | REPORT, SUMMARY, EXECUTIVE, COURT_READY | FINDING, EVIDENCE_ITEM, TIMELINE_EVENT, CORRELATION_GROUP, REPORT_SECTION | `report_synthesis`, `mitre_mapping`, `remediation_planning`, `executive_summary`, `REPORT_SYNTHESIS` |

---

## 3. Specialist Agent Contract & Schema Architecture

Every specialist agent implements the standard `SpecialistAgentContract`:
```python
class SpecialistAgentContract(ABC):
    @abstractmethod
    def analyze_structured_data(
        self,
        structured_data: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Pure structured analysis over approved evidence inputs.
        Returns observations citing source artifact IDs and capability requests if needed.
        """
```

### Analysis Request Schema (`AgentAnalysisRequestRecord`)
- `id`: Unique UUID identifier.
- `case_id`: Scoped case identifier.
- `agent_id`: Target specialist agent ID.
- `analysis_objective`: Deterministic objective describing the inquiry.
- `input_references`: JSON dictionary of input artifact/event/finding IDs.
- `lifecycle_state`: `REGISTERED` -> `READY` -> `RUNNING` -> `COMPLETED` / `WAITING_CAPABILITY` / `BLOCKED` / `FAILED`.
- `sha256_hash`: Cryptographic hash over request parameters.
- `created_by`: User ID of creator.
- `created_at`, `updated_at`, `completed_at`: Standard UTC timestamps.

### Analysis Result Schema (`AgentAnalysisResultRecord`)
- `id`: Unique UUID identifier.
- `request_id`: Originating analysis request ID.
- `case_id`: Scoped case identifier.
- `agent_id`: Producing specialist agent ID.
- `observations`: JSON list of evidence-grounded facts, each citing `source_artifact_id`, `observation_type`, `description`, `field_name`, and `field_value`.
- `capability_requests`: Registered capability requests generated during analysis.
- `storage_path`: POSIX-isolated JSON file on disk.
- `sha256_hash`: Canonical SHA-256 hash computed over result JSON.
- `provenance`: 7-tier provenance references and metadata.

---

## 4. Capability Request Gate & Security Enforcements

The **Capability Request Gate** (`CapabilityRequestGate`) guarantees that agents cannot execute arbitrary code or bypass platform controls:

```
┌─────────────────┐       ┌──────────────────────┐       ┌──────────────────────┐
│ Specialist      │       │ Capability Request   │       │ Step 7 Capability    │
│ Agent           ├──────►│ Gate                 ├──────►│ Registry             │
└─────────────────┘       └──────────┬───────────┘       └──────────┬───────────┘
                                     │                              │
                                     ▼                              ▼
                          ┌──────────────────────┐       ┌──────────────────────┐
                          │ Step 8 Resource      ├──────►│ Step 9 Secure        │
                          │ Scheduler            │       │ Execution Engine     │
                          └──────────────────────┘       └──────────┬───────────┘
                                                                    │
                                                                    ▼
                                                         ┌──────────────────────┐
                                                         │ Steps 10-15 Pipeline │
                                                         │ (Raw -> Structured   │
                                                         │  -> Normalized)      │
                                                         └──────────────────────┘
```

### Safety Rules Enforced by the Gate:
1. **Agent Authorization Check**: Validates that the requesting agent is permitted to invoke the specific capability ID.
2. **Step 7 Tool Registry Check**: Rejects unknown capabilities or inactive tools.
3. **Execution Parameter Sanitation**:
   - Rejects parameters containing `shell`, `cmd`, `exec`, `subprocess`, or `system`.
   - Explicitly blocks `shell=True`.
   - Rejects shell metacharacters: `;`, `|`, `&`, `` ` ``, `$()`.
4. **Cross-Case IDOR Isolation**:
   - Verifies target `evidence_id` belongs exclusively to the authorized `case_id`. Cross-case targeting results in immediate rejection.
5. **Vault Write Protection**:
   - Agents and capability results can never target or overwrite raw evidence vault paths (`data/storage/vault/`).

---

## 5. Storage Isolation, Integrity & Tamper Detection

1. **Storage Path**:
   All agent outputs and execution traces are persisted under:
   `data/storage/agents/cases/{case_id}/`
2. **POSIX Permissions**:
   - Directories created with `0o700` (read/write/execute by owner only).
   - Saved result files written with `0o600` (read/write by owner only).
3. **Path Traversal Defenses**:
   Rejects directory traversal sequences (`..`), relative escapes, and absolute paths outside the designated case directory.
4. **Cryptographic SHA-256 Integrity**:
   - Every result is saved as canonical JSON (`sort_keys=True`, UTF-8 encoded).
   - `verify_result_integrity(db, result_id)` recomputes the on-disk SHA-256 and compares it against the database hash.
   - Any file modification, truncation, or appended whitespace triggers `TAMPER_DETECTED`.
5. **Hash-Chained Lifecycle Audit**:
   Every state transition produces an `AgentLifecycleEvent` recording `from_state`, `to_state`, `event_hash`, and `prev_event_hash`, establishing an unbroken cryptographic chain of custody.

---

## 6. REST API Endpoints & RBAC

The Specialist Agent subsystem exposes case-scoped, RBAC-protected REST endpoints mounted at `/api/v1/cases/{case_id}/agents`:

- `GET /api/v1/cases/{case_id}/agents`: List all registered agents (optional `?enabled_only=true`).
- `GET /api/v1/cases/{case_id}/agents/{agent_id}`: Inspect specific agent metadata and safety profile.
- `POST /api/v1/cases/{case_id}/agents/{agent_id}/toggle`: Enable or disable an agent.
- `POST /api/v1/cases/{case_id}/agents/analysis-requests`: Create a new structured analysis request.
- `POST /api/v1/cases/{case_id}/agents/analysis-requests/{request_id}/execute`: Execute analysis synchronously.
- `POST /api/v1/cases/{case_id}/agents/capability-requests`: Validate and submit a gated capability request.
- `GET /api/v1/cases/{case_id}/agents/analysis-results/{result_id}/integrity`: Perform real-time cryptographic integrity check.
- `GET /api/v1/cases/{case_id}/agents/analysis-requests/{request_id}/provenance`: Retrieve 7-tier provenance trace.

All endpoints require active user credentials and verify case membership/ownership (`get_authorized_case`). Cross-case IDOR access is strictly rejected with `HTTP 403 Forbidden` or `HTTP 404 Not Found`.

---

## 7. Verification & Test Suite Summary

The subsystem has been verified against the full test matrix:

| Test Suite | Purpose | Tests | Status |
| :--- | :--- | :--- | :--- |
| `backend/tests/test_specialist_agent_subsystem.py` | Step 16 agent registry, all 11 agents, capability gate, IDOR, lifecycle, SHA-256 integrity, isolated storage, REST API | 12 | **12 / 12 PASSED** |
| `tests/test_*agent*.py` | Legacy unit tests for disk, log, malware, memory agents | 26 | **26 / 26 PASSED** |
| `backend/tests/test_raw_outputs_subsystem.py` | Step 10 Raw Forensic Outputs regression | 16 | **16 / 16 PASSED** |
| `backend/tests/test_artifact_extraction_subsystem.py` | Step 11 Structured Artifact Extraction regression | 13 | **13 / 13 PASSED** |
| `backend/tests/test_artifact_normalization_subsystem.py` | Step 12 Normalized Artifacts regression | 14 | **14 / 14 PASSED** |
| `backend/tests/test_unified_timeline_subsystem.py` | Step 13 Unified Timeline regression | 14 | **14 / 14 PASSED** |
| `backend/tests/test_cross_domain_correlation_subsystem.py` | Step 14 Cross-Domain Correlation regression | 14 | **14 / 14 PASSED** |
| `backend/tests/test_deterministic_findings_subsystem.py` | Step 15 Deterministic Findings regression | 18 | **18 / 18 PASSED** |
| `frontend` | TypeScript compilation & Vite production build (`npm run build`) | N/A | **BUILT (0 errors)** |
