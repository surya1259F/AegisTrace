# ADFIR — Raw Forensic Outputs Subsystem (Phase 2 / Step 10)

## 1. Subsystem Overview & Core Principles

The **Raw Forensic Outputs Subsystem** registers and manages all raw, unprocessed outputs and execution streams produced by forensic tools executed under Step 9.

```
                    ┌────────────────────────────┐
                    │ Step 9: Forensic           │
                    │ Process Execution          │
                    └─────────────┬──────────────┘
                                  │
                                  ▼
              ┌────────────────────────────────────────┐
              │ Step 10: Raw Output Registration       │
              │  - Tool Output Files & Artifacts       │
              │  - Separate stdout & stderr Streams    │
              │  - SHA-256 Cryptographic Hashing       │
              │  - Duplicate Identity Prevention       │
              │  - Isolated Output Area Storage        │
              └───────────────────┬────────────────────┘
                                  │
                                  ▼
                    ┌────────────────────────────┐
                    │ Registered Raw Outputs     │
                    │ (Evidence-Derived Data)    │
                    └────────────────────────────┘
```

### Strict Forensic Boundaries
1. **Evidence-Derived Data, NOT Conclusions**: Raw outputs are evidence-derived records of tool execution (dump files, raw text, stdout/stderr streams). They are **NOT** conclusions or findings.
2. **Stdout and Stderr Preserved Without Interpretation**: Console streams are registered verbatim as separate raw artifacts with independent hashes. They are not parsed or interpreted at this stage.
3. **Vault Isolation**: Raw outputs are never written into the evidence vault (`data/evidence/vault`). Output storage is isolated under `data/storage/outputs/cases/{case_id}/{execution_id}/`.
4. **Immutability & Anti-Overwrite**: Output files are saved with restricted permissions (`0o600` files, `0o700` directories) and existing outputs are never silently overwritten.

---

## 2. Database Model & Schema Migration

### Table: `execution_outputs` (Alembic Revision `009_raw_forensic_outputs_schema`)

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `id` | String (UUID) | No | Primary key |
| `case_id` | String | No | Foreign key (`cases.id`, CASCADE) |
| `evidence_id` | String | Yes | Foreign key (`evidence_items.id`, SET NULL) |
| `execution_id` | String | No | Foreign key (`forensic_executions.id`, CASCADE) |
| `request_id` | String | Yes | Foreign key (`analysis_requests.id`, SET NULL) |
| `task_id` | String | Yes | Investigation plan task ID |
| `tool_id` | String | Yes | Executed tool ID |
| `tool_version` | String | Yes | Executed tool version |
| `output_type` | String | No | `TOOL_OUTPUT`, `STDOUT`, `STDERR`, `LOG` |
| `filename` | String | No | Output filename or stream reference |
| `storage_path` | String | No | Absolute isolated storage path on disk |
| `size_bytes` | BigInteger | No | File size in bytes |
| `mime_type` | String | Yes | MIME type detection string |
| `sha256_hash` | String(64) | No | SHA-256 hash of output bytes |
| `execution_status` | String | No | Status of parent execution |
| `exit_code` | Integer | Yes | Exit code of execution process |
| `start_time` | DateTime | Yes | Start timestamp |
| `end_time` | DateTime | Yes | End timestamp |
| `created_at` | DateTime | No | Registration timestamp |

---

## 3. Storage Containment & Permissions

- **Path Template**:
  `data/storage/outputs/cases/{case_id}/{execution_id}/{filename}`
- **Directory Permissions**: `0o700` (`drwx------`)
- **File Permissions**: `0o600` (`-rw-------`)
- **Vault Protection**: Path validation guarantees that no raw output file path can overlap or enter `data/evidence/vault`.

---

## 4. REST API Reference

All routes are nested under `/api/v1/cases/{case_id}`:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/cases/{case_id}/executions/{execution_id}/outputs` | Lists raw outputs for an execution, filterable by `output_type`. |
| `GET` | `/cases/{case_id}/executions/{execution_id}/outputs/{output_id}` | Retrieves metadata and execution context for a raw output. |
| `GET` | `/cases/{case_id}/executions/{execution_id}/outputs/{output_id}/integrity` | Verifies SHA-256 hash against current stored bytes. |
| `GET` | `/cases/{case_id}/executions/{execution_id}/outputs/{output_id}/download` | Streams raw output file content with safe MIME types. |
| `GET` | `/cases/{case_id}/analysis-requests/{request_id}/outputs` | Lists raw outputs associated with an analysis request. |

