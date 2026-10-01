# ADFIR — Structured Artifact Extraction Subsystem (Phase 2 / Step 11)

## 1. Subsystem Overview & Core Principles

The **Structured Artifact Extraction Subsystem** converts Step 10 raw forensic execution outputs (`ExecutionOutput`) into structured, normalized, and queryable forensic artifacts (`StructuredArtifact`).

```
                    ┌────────────────────────┐
                    │ Step 10: Raw Outputs   │
                    │ (Files, stdout, stderr)│
                    └───────────┬────────────┘
                                │
                                ▼
            ┌────────────────────────────────────────┐
            │ Step 11: Artifact Extraction Engine    │
            │  - ArtifactParserRegistry              │
            │  - Specialized Parsers (fls, evtx, …)  │
            │  - Field Normalization                 │
            │  - Cryptographic Provenance Chaining   │
            │  - Isolated Artifact Storage           │
            └───────────────────┬────────────────────┘
                                │
                                ▼
                    ┌────────────────────────┐
                    │ Structured Artifacts   │
                    │ (Evidence-Derived Data)│
                    └────────────────────────┘
```

### Strict Forensic Boundaries
1. **Evidence-Derived Data, NOT Conclusions**: Structured artifacts are direct structured representations of parsed raw tool outputs (e.g., directory entries, event log records, memory process rows). They are **NOT** conclusions, findings, or verdicts.
2. **NO Threat Interpretation**: The extraction engine does **NOT** detect attacks, infer attacker intent, correlate cross-domain entities, calculate threat severity, or invoke LLM reasoning.
3. **Immutability of Raw Outputs & Evidence Vault**: Raw outputs and vault files are strictly read-only. Their byte contents, sizes, and SHA-256 hashes are verified and never modified.
4. **No Dropped Outputs**: Any raw output that cannot be matched to a registered parser is recorded as `extraction_status="UNSUPPORTED"` with documented rationale and audit event logging. Missing records are never invented.

---

## 2. Database Model & Schema Migration

### Table: `structured_artifacts` (Alembic Revision `010_structured_artifacts_schema`)

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `id` | String (UUID) | No | Primary key |
| `case_id` | String | No | Foreign key (`cases.id`, CASCADE) |
| `evidence_id` | String | Yes | Foreign key (`evidence_items.id`, SET NULL) |
| `execution_id` | String | No | Foreign key (`forensic_executions.id`, CASCADE) |
| `raw_output_id` | String | No | Foreign key (`execution_outputs.id`, CASCADE) |
| `request_id` | String | Yes | Foreign key (`analysis_requests.id`, SET NULL) |
| `task_id` | String | Yes | Investigation plan task ID |
| `tool_id` | String | Yes | Generating tool identifier |
| `tool_version` | String | Yes | Version of the tool that produced the output |
| `parser_name` | String | No | Authoritative parser class identifier |
| `parser_version` | String | No | Version of parser implementation |
| `artifact_type` | String | No | Domain classification (`FILESYSTEM_RECORD`, `EVENT_LOG_RECORD`, etc.) |
| `source_reference` | String | Yes | Lineage reference (e.g. `inode:1024:path`, `event:4624:DC01`) |
| `normalized_data` | JSON | No | Canonical normalized key-value fields |
| `raw_record` | Text | Yes | Exact unparsed raw string line or JSON chunk |
| `sha256_hash` | String(64) | No | SHA-256 of canonical serialized `normalized_data` |
| `source_raw_output_hash` | String(64) | No | SHA-256 hash of the parent `ExecutionOutput` |
| `storage_path` | String | Yes | Absolute path to serialized JSON artifact on disk |
| `extraction_status` | String | No | `EXTRACTED`, `UNSUPPORTED`, `PARSE_ERROR` |
| `error_message` | Text | Yes | Error detail or explanation for unsupported status |
| `created_at` | DateTime | No | UTC timestamp of extraction |

---

## 3. Parser Registry & Supported Forensic Tools

The parser registry evaluates raw output attributes (tool ID, filename, header structure, content sample) and dynamically selects the most specific parser:

| Parser | Target Domain | Supported Tools | Output Artifact Type |
| :--- | :--- | :--- | :--- |
| **`FlsArtifactParser`** | Filesystem | SleuthKit (`fls`, `sleuthkit_fls`, bodyfiles) | `FILESYSTEM_RECORD` |
| **`EvtxArtifactParser`** | Windows Events | EVTX dumpers (`winevtx`, `evtx_dump`, `python_evtx`) | `EVENT_LOG_RECORD` |
| **`YaraArtifactParser`** | Malware Matches | YARA (`yara`, `yara_scanner`) | `MALWARE_MATCH` |
| **`PsListArtifactParser`** | Volatile Processes | Volatility (`pslist`, `volatility_pslist`) | `PROCESS_RECORD` |
| **`NetScanArtifactParser`** | Network Sockets | Volatility (`netscan`, `volatility_netscan`) | `NETWORK_RECORD` |
| **`ExifToolArtifactParser`** | File Metadata | ExifTool (`exiftool`, metadata dumps) | `METADATA_RECORD` |
| **`GenericStructuredTextParser`** | Structured JSON / KV | Fallback for valid JSON objects / arrays | `GENERIC_RECORD` |
| **Unsupported Fallback** | Unknown / Binary | Any unrecognized raw tool output | `UNSUPPORTED_OUTPUT` |

---

## 4. Cryptographic Lineage & Storage Isolation

### Provenance Chaining
Each structured artifact maintains end-to-end cryptographic lineage:
$$\text{EvidenceItem (Vault)} \longrightarrow \text{ForensicExecution (Workspace)} \longrightarrow \text{ExecutionOutput (Raw)} \longrightarrow \text{StructuredArtifact (Normalized)}$$

### Storage Isolation
- Serialized JSON artifacts are stored under:
  `data/storage/artifacts/cases/{case_id}/{execution_id}/{artifact_id}.json`
- Directory permissions: `0o700` (`rwx------`).
- File permissions: `0o600` (`rw-------`).
- Vault isolation: Storage path verification explicitly prohibits locating artifacts inside the evidence vault directory (`data/evidence/vault`).

---

## 5. REST API Reference

All endpoints enforce multi-tenant case isolation, session authorization, and IDOR protection.

### 1. Trigger Execution Extraction
- **Endpoint**: `POST /api/v1/cases/{case_id}/executions/{execution_id}/extract-artifacts`
- **Response**: `ArtifactExtractionBatchResponse`
```json
{
  "execution_id": "c91f56fa-...",
  "total_raw_outputs": 3,
  "processed_outputs": 3,
  "extracted_artifacts_count": 24,
  "unsupported_outputs_count": 1,
  "artifacts": [...]
}
```

### 2. Trigger Single Output Extraction
- **Endpoint**: `POST /api/v1/cases/{case_id}/raw-outputs/{output_id}/extract-artifacts`
- **Response**: `List[StructuredArtifactResponse]`

### 3. List Execution Artifacts
- **Endpoint**: `GET /api/v1/cases/{case_id}/executions/{execution_id}/artifacts`
- **Query Params**: `artifact_type`, `extraction_status`, `skip`, `limit`
- **Response**: `List[StructuredArtifactResponse]`

### 4. List Evidence-Level Artifacts
- **Endpoint**: `GET /api/v1/cases/{case_id}/evidence/{evidence_id}/artifacts`
- **Query Params**: `artifact_type`, `skip`, `limit`
- **Response**: `List[StructuredArtifactResponse]`

### 5. Inspect Artifact Details
- **Endpoint**: `GET /api/v1/cases/{case_id}/artifacts/{artifact_id}`
- **Response**: `StructuredArtifactResponse`

### 6. Verify Artifact Cryptographic Integrity
- **Endpoint**: `GET /api/v1/cases/{case_id}/artifacts/{artifact_id}/integrity`
- **Response**: `ArtifactIntegrityResponse`
```json
{
  "artifact_id": "767053d9-...",
  "artifact_type": "FILESYSTEM_RECORD",
  "expected_sha256": "35d30920c...",
  "calculated_sha256": "35d30920c...",
  "source_raw_output_hash": "e28bd988c...",
  "raw_output_current_hash": "e28bd988c...",
  "integrity_status": "VALID",
  "provenance_chain": {
    "case_id": "case-123",
    "evidence_id": "ev-456",
    "execution_id": "exec-789",
    "raw_output_id": "out-012",
    "tool_id": "fls",
    "parser_name": "FlsArtifactParser",
    "extraction_status": "EXTRACTED"
  },
  "checked_at": "2026-09-26T08:20:00Z"
}
```

### 7. Download Serialized Artifact JSON
- **Endpoint**: `GET /api/v1/cases/{case_id}/artifacts/{artifact_id}/download`
- **Response**: `FileResponse` (`application/json`) with path isolation check.

---

## 6. Verification & Test Suite Summary

The subsystem is validated with comprehensive automated test suites:

- **Step 11 Test Suite (`backend/tests/test_artifact_extraction_subsystem.py`)**:
  - `test_parser_selection_registry`: Verified deterministic selection across fls, evtx, yara, pslist, netscan, exiftool, generic.
  - `test_fls_filesystem_artifact_extraction`: Verified fls inode, mode, and deleted flag extraction.
  - `test_evtx_event_log_artifact_extraction`: Verified event ID, computer, timestamp, channel normalization.
  - `test_yara_malware_match_artifact_extraction`: Verified rule name, target path, tag extraction.
  - `test_volatility_pslist_and_netscan_extraction`: Verified process table and network connection records.
  - `test_exiftool_metadata_artifact_extraction`: Verified image and file metadata records.
  - `test_unsupported_output_recorded_explicitly`: Verified unsupported outputs are recorded as `UNSUPPORTED` and audited.
  - `test_artifact_integrity_verification_passed`: Verified SHA-256 and lineage check for intact records.
  - `test_artifact_integrity_tamper_detected`: Verified detection of modified payload as `TAMPERED`.
  - `test_artifact_integrity_missing_storage_file`: Verified missing file detected as `FILE_MISSING`.
  - `test_storage_separation_and_permissions`: Verified storage directory separation and `0o600`/`0o700` permissions.
  - `test_prohibition_of_vault_storage`: Verified rejection of storage attempts inside the evidence vault.
  - `test_raw_output_immutability`: Verified raw outputs remain strictly unmodified in bytes, size, and hash.
  - `test_api_trigger_execution_extraction_and_list`: Verified execution-level extraction and listing with type filters.
  - `test_api_evidence_level_artifacts_and_details`: Verified evidence artifact queries, details, and downloads.
  - `test_case_authorization_and_idor_isolation`: Verified RBAC enforcement and cross-case IDOR denial.
  - `test_strict_boundary_invariants`: Verified absence of conclusions, findings, or threat interpretations.

- **Full Regression Status across Steps 6–11**:
  - Step 6 Investigation Strategy Engine: **20/20 PASSED**
  - Step 7 Tool Selection Subsystem: **14/14 PASSED**
  - Step 8 Resource-Aware Scheduler: **17/17 PASSED**
  - Step 9 Secure Forensic Execution: **18/18 PASSED**
  - Step 10 Raw Forensic Outputs: **16/16 PASSED**
  - Step 11 Structured Artifact Extraction: **17/17 PASSED**
  - **Total: 102/102 PASSED**
  - **Frontend Build (`npm run build`)**: **SUCCESS**
  - **Tauri Rust Backend (`cargo check`)**: **SUCCESS**
