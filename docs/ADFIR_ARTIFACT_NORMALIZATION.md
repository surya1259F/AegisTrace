# ADFIR — Artifact Normalization Subsystem (Phase 2 / Step 12)

## 1. Subsystem Overview & Core Principles

The **Artifact Normalization Subsystem** converts Step 11 structured artifacts (`StructuredArtifact`) into a common, unified entity schema (`NormalizedArtifact`). This enables cross-tool, cross-domain forensic comparison without losing underlying source provenance or inventing non-existent entity identities.

```
                    ┌────────────────────────────┐
                    │ Step 11: Structured        │
                    │ Artifacts (Tool Parsers)   │
                    └─────────────┬──────────────┘
                                  │
                                  ▼
              ┌────────────────────────────────────────┐
              │ Step 12: Artifact Normalization Engine │
              │  - Entity Mapping & Normalization      │
              │  - Deterministic Entity Fingerprinting │
              │  - Multi-Source Reference Tracking     │
              │  - Tamper Detection (SHA-256)          │
              │  - Isolated Canonical Entity Storage   │
              └───────────────────┬────────────────────┘
                                  │
                                  ▼
                    ┌────────────────────────────┐
                    │ Normalized Artifacts       │
                    │ (Canonical Entities)       │
                    └────────────────────────────┘
```

### Strict Forensic Boundaries
1. **Evidence-Derived Data, NOT Conclusions**: Normalized artifacts are canonical data representations (file entities, process entities, socket entities, event records). They are **NOT** attack hypotheses, verdicts, or conclusions.
2. **NO Threat Interpretation**: The normalization engine does **NOT**:
   - Detect attacks or intrusions.
   - Infer attacker tactics or motivations.
   - Correlate unrelated entities across arbitrary domains.
   - Calculate threat or severity scores.
   - Invoke LLMs or heuristic analyzers.
3. **Immutability of Step 10 & 11**: Raw outputs and structured artifacts are strictly immutable and never altered.
4. **Deterministic Identity Without Invention**: Canonical entity identities are constructed strictly from deterministic, non-empty source attributes (e.g. `filepath`, `sha256`, `pid`, `local_ip:local_port`). When insufficient data exists, `entity_identity` is preserved as `None` or partial without guessing.

---

## 2. Database Model & Schema Migration

### Table: `normalized_artifacts` (Alembic Revision `011_artifact_normalization_schema`)

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `id` | String (UUID) | No | Primary key |
| `case_id` | String | No | Foreign key (`cases.id`, CASCADE) |
| `evidence_id` | String | Yes | Foreign key (`evidence_items.id`, SET NULL) |
| `execution_id` | String | No | Foreign key (`forensic_executions.id`, CASCADE) |
| `source_artifact_id` | String | No | Primary contributing `StructuredArtifact` ID |
| `raw_output_id` | String | Yes | Foreign key (`execution_outputs.id`, SET NULL) |
| `entity_type` | String | No | Canonical entity type (`FILE_SYSTEM_ENTRY`, `PROCESS_INSTANCE`, etc.) |
| `entity_identity` | String | Yes | Deterministic fingerprint (e.g., `file:/etc/passwd`, `proc:412:ls`) |
| `normalized_fields` | JSON | No | Canonical normalized key-value fields |
| `source_references` | JSON | No | Array of source lineage references |
| `source_artifact_ids` | JSON | No | List of all contributing structured artifact IDs |
| `source_artifact_hashes`| JSON | No | List of all contributing structured artifact SHA-256 hashes |
| `contributing_tool_count`| Integer | No | Count of distinct tools/parsers contributing |
| `sha256_hash` | String(64) | No | SHA-256 of canonical normalized representation |
| `source_artifact_hash` | String(64) | No | SHA-256 of primary contributing `StructuredArtifact` |
| `storage_path` | String | Yes | Isolated file storage path |
| `normalization_status` | String | No | `NORMALIZED`, `PARTIALLY_NORMALIZED`, `UNSUPPORTED` |
| `created_at` | DateTime | No | Creation timestamp |

---

## 3. Storage Containment & Security

- **Path Template**:
  `data/storage/normalized/cases/{case_id}/{execution_id}/{normalized_id}.json`
- **File System Permissions**:
  - Directories: `0o700` (`drwx------`)
  - Artifact files: `0o600` (`-rw-------`)
- **Evidence Vault Isolation**:
  Storage path validation strictly prevents writing into `data/evidence/vault`.

---

## 4. REST API Reference

All routes are nested under `/api/v1/cases/{case_id}`:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/cases/{case_id}/executions/{execution_id}/normalize` | Normalizes structured artifacts produced by an execution. |
| `POST` | `/cases/{case_id}/structured-artifacts/{artifact_id}/normalize` | Normalizes a single structured artifact. |
| `GET` | `/cases/{case_id}/normalized-artifacts` | Lists normalized artifacts with filtering (`entity_type`, `execution_id`, `evidence_id`, `entity_identity`, pagination). |
| `GET` | `/cases/{case_id}/normalized-artifacts/{artifact_id}` | Retrieves normalized artifact metadata and canonical payload. |
| `GET` | `/cases/{case_id}/normalized-artifacts/{artifact_id}/integrity` | Verifies SHA-256 cryptographic integrity and checks for tampering. |
| `GET` | `/cases/{case_id}/normalized-artifacts/{artifact_id}/download` | Downloads canonical serialized normalized JSON artifact. |

